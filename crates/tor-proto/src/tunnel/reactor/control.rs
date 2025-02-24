//! Module providing [`CtrlMsg`].

use super::{
    CircuitHandshake, CloseStreamBehavior, MetaCellHandler, Reactor, ReactorResultChannel,
    RunOnceCmdInner, SendRelayCell,
};
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{HopNum, InboundClientLayer, OutboundClientLayer, Tor1RelayCrypto};
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::stream::AnyCmdChecker;
use crate::tunnel::circuit::celltypes::CreateResponse;
use crate::tunnel::circuit::{path, CircParameters};
use crate::tunnel::reactor::extender::CircuitExtender;
use crate::tunnel::reactor::{NtorClient, ReactorError};
use crate::tunnel::streammap;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::relaycell::msg::{AnyRelayMsg, Sendme};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellFormat, RelayCellFormatTrait, RelayCellFormatV0, StreamId,
    UnparsedRelayMsg,
};
use tor_error::internal;
use tracing::trace;
#[cfg(feature = "hs-service")]
use {
    super::StreamReqSender, crate::stream::IncomingStreamRequestFilter,
    crate::tunnel::reactor::IncomingStreamRequestHandler,
};

#[cfg(test)]
use crate::congestion::sendme::CircTag;

use oneshot_fused_workaround as oneshot;

use crate::crypto::handshake::ntor::NtorPublicKey;
use crate::tunnel::circuit::{StreamMpscReceiver, StreamMpscSender};
use tor_linkspec::{EncodedLinkSpec, OwnedChanTarget};

use std::result::Result as StdResult;

/// A message telling the reactor to do something.
///
/// The difference between this and [`CtrlCmd`] is that `CtrlMsg`s
/// are only handled when the reactor's `chan_sender` is ready to receive cells,
/// whereas `CtrlCmd` are handled immediately as they arrive.
///
/// For each `CtrlMsg`, the reactor will send a cell on the underlying channel.
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
        params: CircParameters,
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
        /// Other parameters relevant for circuit extension.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Extend a circuit by one hop, using the ntorv3 handshake.
    #[cfg(feature = "ntor_v3")]
    ExtendNtorV3 {
        /// The peer that we're extending to.
        ///
        /// Used to extend our record of the circuit's path.
        peer_id: OwnedChanTarget,
        /// The handshake type to use for this hop.
        public_key: NtorV3PublicKey,
        /// Information about how to connect to the relay we're extending to.
        linkspecs: Vec<EncodedLinkSpec>,
        /// Other parameters relevant for circuit extension.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Begin a stream with the provided hop in this circuit.
    ///
    /// Allocates a stream ID, and sends the provided message to that hop.
    BeginStream {
        /// The hop number to begin the stream with.
        hop_num: HopNum,
        /// The message to send.
        message: AnyRelayMsg,
        /// A channel to send messages on this stream down.
        ///
        /// This sender shouldn't ever block, because we use congestion control and only send
        /// SENDME cells once we've read enough out of the other end. If it *does* block, we
        /// can assume someone is trying to send us more cells than they should, and abort
        /// the stream.
        sender: StreamMpscSender<UnparsedRelayMsg>,
        /// A channel to receive messages to send on this stream from.
        rx: StreamMpscReceiver<AnyRelayMsg>,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<StreamId>,
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
        hop_num: HopNum,
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
        hop_num: HopNum,
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
    /// Send a SENDME cell (used to ask for more data to be sent) on the given stream.
    SendSendme {
        /// The stream ID to send a SENDME for.
        stream_id: StreamId,
        /// The hop number the stream is on.
        hop_num: HopNum,
    },
    /// Get the clock skew claimed by the first hop of the circuit.
    FirstHopClockSkew {
        /// Oneshot channel to return the clock skew.
        answer: oneshot::Sender<ClockSkew>,
    },
}

/// A message telling the reactor to do something.
///
/// The difference between this and [`CtrlMsg`] is that `CtrlCmd`s
/// are handled even if the reactor's `chan_sender` is not ready to receive cells.
/// Another difference is that `CtrlCmd`s never cause cells to sent on the channel,
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
        /// Which relay cell format to use for this hop.
        relay_cell_format: RelayCellFormat,
        /// The cryptographic algorithms and keys to use when communicating with
        /// the newly added hop.
        #[educe(Debug(ignore))]
        cell_crypto: (
            Box<dyn OutboundClientLayer + Send>,
            Box<dyn InboundClientLayer + Send>,
            Option<CircuitBinding>,
        ),
        /// A set of parameters used to configure this hop.
        params: CircParameters,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
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
        hop_num: HopNum,
        /// A filter used to check requests before passing them on.
        #[educe(Debug(ignore))]
        #[cfg(feature = "hs-service")]
        filter: Box<dyn IncomingStreamRequestFilter>,
    },
    /// (tests only) Add a hop to the list of hops on this circuit, with dummy cryptography.
    #[cfg(test)]
    AddFakeHop {
        relay_cell_format: RelayCellFormat,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        params: CircParameters,
        done: ReactorResultChannel<()>,
    },
    /// (tests only) Get the send window and expected tags for a given hop.
    #[cfg(test)]
    QuerySendWindow {
        hop: HopNum,
        done: ReactorResultChannel<(u32, Vec<CircTag>)>,
    },
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
    pub(super) fn handle_msg(&mut self, msg: CtrlMsg) -> Result<RunOnceCmdInner> {
        trace!("{}: reactor received {:?}", self.reactor.unique_id, msg);
        match msg {
            // This is handled earlier, since it requires blocking.
            CtrlMsg::Create { .. } => panic!("got a CtrlMsg::Create in handle_control"),
            CtrlMsg::ExtendNtor {
                peer_id,
                public_key,
                linkspecs,
                params,
                done,
            } => {
                // ntor handshake only supports V0.
                /// Local type alias to ensure consistency below.
                type Rcf = RelayCellFormatV0;

                let (extender, cell) =
                    CircuitExtender::<NtorClient, Tor1RelayCrypto<Rcf>, _, _>::begin(
                        Rcf::FORMAT,
                        peer_id,
                        HandshakeType::NTOR,
                        &public_key,
                        linkspecs,
                        params,
                        &(),
                        self.reactor,
                        done,
                    )?;
                self.reactor.set_meta_handler(Box::new(extender))?;

                Ok(RunOnceCmdInner::Send { cell, done: None })
            }
            #[cfg(feature = "ntor_v3")]
            CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key,
                linkspecs,
                params,
                done,
            } => {
                // TODO #1067: support negotiating other formats.
                /// Local type alias to ensure consistency below.
                type Rcf = RelayCellFormatV0;

                // TODO: Set extensions, e.g. based on `params`.
                let client_extensions = [];

                let (extender, cell) =
                    CircuitExtender::<NtorV3Client, Tor1RelayCrypto<Rcf>, _, _>::begin(
                        Rcf::FORMAT,
                        peer_id,
                        HandshakeType::NTOR_V3,
                        &public_key,
                        linkspecs,
                        params,
                        &client_extensions,
                        self.reactor,
                        done,
                    )?;
                self.reactor.set_meta_handler(Box::new(extender))?;

                Ok(RunOnceCmdInner::Send { cell, done: None })
            }
            CtrlMsg::BeginStream {
                hop_num,
                message,
                sender,
                rx,
                done,
                cmd_checker,
            } => {
                let Some(hop) = self.reactor.hop_mut(hop_num) else {
                    return Err(Error::from(internal!(
                        "{}: Attempting to send a BEGIN cell to an unknown hop {hop_num:?}",
                        self.reactor.unique_id,
                    )));
                };
                let cell = hop.begin_stream(message, sender, rx, cmd_checker);
                Ok(RunOnceCmdInner::BeginStream { cell, done })
            }
            #[cfg(feature = "hs-service")]
            CtrlMsg::ClosePendingStream {
                hop_num,
                stream_id,
                message,
                done,
            } => Ok(RunOnceCmdInner::CloseStream {
                hop_num,
                sid: stream_id,
                behav: message,
                reason: streammap::TerminateReason::ExplicitEnd,
                done: Some(done),
            }),
            CtrlMsg::SendSendme { stream_id, hop_num } => {
                let sendme = Sendme::new_empty();
                let cell = AnyRelayMsgOuter::new(Some(stream_id), sendme.into());
                let cell = SendRelayCell {
                    hop: hop_num,
                    early: false,
                    cell,
                };
                Ok(RunOnceCmdInner::Send { cell, done: None })
            }
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsg {
                hop_num,
                msg,
                sender,
            } => {
                let cell = AnyRelayMsgOuter::new(None, msg);
                let cell = SendRelayCell {
                    hop: hop_num,
                    early: false,
                    cell,
                };
                Ok(RunOnceCmdInner::Send {
                    cell,
                    done: Some(sender),
                })
            }
            #[cfg(feature = "send-control-msg")]
            CtrlMsg::SendMsgAndInstallHandler {
                msg,
                handler,
                sender,
            } => Ok(RunOnceCmdInner::SendMsgAndInstallHandler {
                msg,
                handler,
                done: sender,
            }),
            CtrlMsg::FirstHopClockSkew { answer } => {
                Ok(RunOnceCmdInner::FirstHopClockSkew { answer })
            }
        }
    }

    /// Handle a control command.
    pub(super) fn handle_cmd(&mut self, msg: CtrlCmd) -> StdResult<(), ReactorError> {
        trace!("{}: reactor received {:?}", self.reactor.unique_id, msg);
        match msg {
            CtrlCmd::Shutdown => Err(ReactorError::Shutdown),
            #[cfg(feature = "hs-common")]
            #[allow(unreachable_code)]
            CtrlCmd::ExtendVirtual {
                relay_cell_format: format,
                cell_crypto,
                params,
                done,
            } => {
                let (outbound, inbound, binding) = cell_crypto;

                // TODO HS: Perhaps this should describe the onion service, or
                // describe why the virtual hop was added, or something?
                let peer_id = path::HopDetail::Virtual;

                self.reactor
                    .add_hop(format, peer_id, outbound, inbound, binding, &params);
                let _ = done.send(Ok(()));

                Ok(())
            }
            #[cfg(feature = "hs-service")]
            CtrlCmd::AwaitStreamRequest {
                cmd_checker,
                incoming_sender,
                hop_num,
                done,
                filter,
            } => {
                // TODO: At some point we might want to add a CtrlCmd for
                // de-registering the handler.  See comments on `allow_stream_requests`.
                let handler = IncomingStreamRequestHandler {
                    incoming_sender,
                    cmd_checker,
                    hop_num,
                    filter,
                };

                let ret = self.reactor.set_incoming_stream_req_handler(handler);
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.

                Ok(())
            }
            #[cfg(test)]
            CtrlCmd::AddFakeHop {
                relay_cell_format,
                fwd_lasthop,
                rev_lasthop,
                params,
                done,
            } => {
                self.reactor.handle_add_fake_hop(
                    relay_cell_format,
                    fwd_lasthop,
                    rev_lasthop,
                    &params,
                    done,
                );

                Ok(())
            }
            #[cfg(test)]
            CtrlCmd::QuerySendWindow { hop, done } => {
                let _ = done.send(if let Some(hop) = self.reactor.hop_mut(hop) {
                    Ok(hop.ccontrol.send_window_and_expected_tags())
                } else {
                    Err(Error::from(internal!(
                        "received QuerySendWindow for unknown hop {}",
                        hop.display()
                    )))
                });

                Ok(())
            }
        }
    }
}
