//! Module exposing types for representing circuits in the tunnel reactor.

pub(crate) mod circhop;
pub(super) mod create;
pub(super) mod extender;

use crate::channel::Channel;
use crate::circuit::UniqId;
use crate::circuit::cell_sender::CircuitCellSender;
use crate::circuit::celltypes::{ClientCircChanMsg, CreateResponse};
use crate::circuit::circhop::HopSettings;
use crate::client::circuit::handshake::{BoxedClientLayer, HandshakeRole};
use crate::client::circuit::padding::{
    self, PaddingController, PaddingEventStream, QueuedCellPaddingInfo,
};
use crate::client::circuit::{CircuitRxReceiver, MutableState};
use crate::client::circuit::{TimeoutEstimator, path};
use crate::client::reactor::MetaCellDisposition;
use crate::congestion::CongestionSignals;
use crate::congestion::sendme;
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    HopNum, InboundClientCrypt, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody,
};
use crate::crypto::handshake::fast::CreateFastClient;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::crypto::handshake::ntor_v3::{NtorV3Client, NtorV3PublicKey};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::memquota::{CircuitAccount, SpecificAccount as _, StreamAccount};
use crate::stream::StreamMpscReceiver;
use crate::stream::cmdcheck::{AnyCmdChecker, StreamStatus};
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::flow_ctrl::xon_xoff::reader::DrainRateRequest;
use crate::stream::queue::{StreamQueueSender, stream_queue};
use crate::streammap;
use crate::tunnel::TunnelScopedCircId;
use crate::util::err::ReactorError;
use crate::util::notify::NotifySender;
use crate::{ClockSkew, Error, Result};

use tor_async_utils::{SinkTrySend as _, SinkTrySendError as _};
use tor_cell::chancell::msg::{AnyChanMsg, HandshakeType, Relay};
use tor_cell::chancell::{AnyChanCell, ChanCmd, CircId};
use tor_cell::chancell::{BoxedCellBody, ChanMsg};
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme, SendmeTag, Truncated};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoderResult, RelayCellFormat, RelayCmd, StreamId, UnparsedRelayMsg,
};
use tor_error::{Bug, internal};
use tor_linkspec::RelayIds;
use tor_llcrypto::pk;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};

use futures::SinkExt as _;
use oneshot_fused_workaround as oneshot;
use postage::watch;
use safelog::sensitive as sv;
use tor_rtcompat::{DynTimeProvider, SleepProvider as _};
use tracing::{debug, trace, warn};

use super::{
    CellHandlers, CircuitHandshake, CloseStreamBehavior, ReactorResultChannel, SendRelayCell,
};

use crate::conflux::msghandler::ConfluxStatus;

use std::borrow::Borrow;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use create::{Create2Wrap, CreateFastWrap, CreateHandshakeWrap};
use extender::HandshakeAuxDataHandler;

#[cfg(feature = "hs-service")]
use {
    crate::circuit::CircSyncView,
    crate::client::stream::{InboundDataCmdChecker, IncomingStreamRequest},
    tor_cell::relaycell::msg::Begin,
};

#[cfg(feature = "conflux")]
use {
    crate::conflux::msghandler::{ConfluxAction, ConfluxCmd, ConfluxMsgHandler, OooRelayMsg},
    crate::tunnel::TunnelId,
};

pub(super) use circhop::{CircHop, CircHopList};

/// Initial value for outbound flow-control window on streams.
pub(crate) const SEND_WINDOW_INIT: u16 = 500;
/// Initial value for inbound flow-control window on streams.
pub(crate) const RECV_WINDOW_INIT: u16 = 500;
/// Size of the buffer used between the reactor and a `StreamReader`.
///
/// FIXME(eta): We pick 2× the receive window, which is very conservative (we arguably shouldn't
///             get sent more than the receive window anyway!). We might do due to things that
///             don't count towards the window though.
pub(crate) const STREAM_READER_BUFFER: usize = (2 * RECV_WINDOW_INIT) as usize;

/// A circuit "leg" from a tunnel.
///
/// Regular (non-multipath) circuits have a single leg.
/// Conflux (multipath) circuits have `N` (usually, `N = 2`).
pub(crate) struct Circuit {
    /// The time provider.
    runtime: DynTimeProvider,
    /// The channel this circuit is attached to.
    channel: Arc<Channel>,
    /// Sender object used to actually send cells.
    ///
    /// NOTE: Control messages could potentially add unboundedly to this, although that's
    ///       not likely to happen (and isn't triggereable from the network, either).
    pub(super) chan_sender: CircuitCellSender,
    /// Input stream, on which we receive ChanMsg objects from this circuit's
    /// channel.
    ///
    // TODO: could use a SPSC channel here instead.
    pub(super) input: CircuitRxReceiver,
    /// The cryptographic state for this circuit for inbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit.
    crypto_in: InboundClientCrypt,
    /// The cryptographic state for this circuit for outbound cells.
    crypto_out: OutboundClientCrypt,
    /// List of hops state objects used by the reactor
    pub(super) hops: CircHopList,
    /// Mutable information about this circuit,
    /// shared with the reactor's `ConfluxSet`.
    mutable: Arc<MutableState>,
    /// This circuit's identifier on the upstream channel.
    channel_id: CircId,
    /// An identifier for logging about this reactor's circuit.
    unique_id: TunnelScopedCircId,
    /// A handler for conflux cells.
    ///
    /// Set once the conflux handshake is initiated by the reactor
    /// using [`Reactor::handle_link_circuits`](super::Reactor::handle_link_circuits).
    #[cfg(feature = "conflux")]
    conflux_handler: Option<ConfluxMsgHandler>,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
    /// An event stream telling us about padding-related events.
    //
    // TODO: it would be nice to have all of these streams wrapped in a single
    // SelectAll, but we can't really do that, since we need the ability to move them
    // from one conflux set to another, and a SelectAll doesn't let you actually
    // remove one of its constituent streams.  This issue might get solved along
    // with the the rest of the next reactor refactoring.
    pub(super) padding_event_stream: PaddingEventStream,
    /// Current rules for blocking traffic, according to the padding controller.
    #[cfg(feature = "circ-padding")]
    padding_block: Option<padding::StartBlocking>,
    /// The circuit timeout estimator.
    ///
    /// Used for computing half-stream expiration.
    timeouts: Arc<dyn TimeoutEstimator>,
    /// Memory quota account
    #[allow(dead_code)] // Partly here to keep it alive as long as the circuit
    memquota: CircuitAccount,
}

/// A command to run in response to a circuit event.
///
/// Unlike `RunOnceCmdInner`, doesn't know anything about `UniqId`s.
/// The user of the `CircuitCmd`s is supposed to know the `UniqId`
/// of the circuit the `CircuitCmd` came from.
///
/// This type gets mapped to a `RunOnceCmdInner` in the circuit reactor.
#[derive(Debug, derive_more::From)]
pub(super) enum CircuitCmd {
    /// Send a RELAY cell on the circuit leg this command originates from.
    Send(SendRelayCell),
    /// Handle a SENDME message received on the circuit leg this command originates from.
    HandleSendMe {
        /// The hop number.
        hop: HopNum,
        /// The SENDME message to handle.
        sendme: Sendme,
    },
    /// Close the specified stream on the circuit leg this command originates from.
    CloseStream {
        /// The hop number.
        hop: HopNum,
        /// The ID of the stream to close.
        sid: StreamId,
        /// The stream-closing behavior.
        behav: CloseStreamBehavior,
        /// The reason for closing the stream.
        reason: streammap::TerminateReason,
    },
    /// Perform an action resulting from handling a conflux cell.
    #[cfg(feature = "conflux")]
    Conflux(ConfluxCmd),
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
    /// Enqueue an out-of-order cell in the reactor.
    #[cfg(feature = "conflux")]
    Enqueue(OooRelayMsg),
}

/// Return a `CircProto` error for the specified unsupported cell.
///
/// This error will shut down the reactor.
///
/// Note: this is a macro to simplify usage (this way the caller doesn't
/// need to .map() the result to the appropriate type)
macro_rules! unsupported_client_cell {
    ($msg:expr) => {{
        unsupported_client_cell!(@ $msg, "")
    }};

    ($msg:expr, $hopnum:expr) => {{
        let hop: HopNum = $hopnum;
        let hop_display = format!(" from hop {}", hop.display());
        unsupported_client_cell!(@ $msg, hop_display)
    }};

    (@ $msg:expr, $hopnum_display:expr) => {
        Err(crate::Error::CircProto(format!(
            "Unexpected {} cell{} on client circuit",
            $msg.cmd(),
            $hopnum_display,
        )))
    };
}

pub(super) use unsupported_client_cell;

impl Circuit {
    /// Create a new non-multipath circuit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        runtime: DynTimeProvider,
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: TunnelScopedCircId,
        input: CircuitRxReceiver,
        memquota: CircuitAccount,
        mutable: Arc<MutableState>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        timeouts: Arc<dyn TimeoutEstimator>,
    ) -> Self {
        let chan_sender = CircuitCellSender::from_channel_sender(channel.sender());

        let crypto_out = OutboundClientCrypt::new();
        Circuit {
            runtime,
            channel,
            chan_sender,
            input,
            crypto_in: InboundClientCrypt::new(),
            hops: CircHopList::default(),
            unique_id,
            channel_id,
            crypto_out,
            mutable,
            #[cfg(feature = "conflux")]
            conflux_handler: None,
            padding_ctrl,
            padding_event_stream,
            #[cfg(feature = "circ-padding")]
            padding_block: None,
            timeouts,
            memquota,
        }
    }

    /// Return the process-unique identifier of this circuit.
    pub(super) fn unique_id(&self) -> UniqId {
        self.unique_id.unique_id()
    }

    /// Return the shared mutable state of this circuit.
    pub(super) fn mutable(&self) -> &Arc<MutableState> {
        &self.mutable
    }

    /// Add this circuit to a multipath tunnel, by associating it with a new [`TunnelId`],
    /// and installing a [`ConfluxMsgHandler`] on this circuit.
    ///
    /// Once this is called, the circuit will be able to handle conflux cells.
    #[cfg(feature = "conflux")]
    pub(super) fn add_to_conflux_tunnel(
        &mut self,
        tunnel_id: TunnelId,
        conflux_handler: ConfluxMsgHandler,
    ) {
        self.unique_id = TunnelScopedCircId::new(tunnel_id, self.unique_id.unique_id());
        self.conflux_handler = Some(conflux_handler);
    }

    /// Send a LINK cell to the specified hop.
    ///
    /// This must be called *after* a [`ConfluxMsgHandler`] is installed
    /// on the circuit with [`add_to_conflux_tunnel`](Self::add_to_conflux_tunnel).
    #[cfg(feature = "conflux")]
    pub(super) async fn begin_conflux_link(
        &mut self,
        hop: HopNum,
        cell: AnyRelayMsgOuter,
        runtime: &tor_rtcompat::DynTimeProvider,
    ) -> Result<()> {
        use tor_rtcompat::SleepProvider as _;

        if self.conflux_handler.is_none() {
            return Err(internal!(
                "tried to send LINK cell before installing a ConfluxMsgHandler?!"
            )
            .into());
        }

        let cell = SendRelayCell {
            hop: Some(hop),
            early: false,
            cell,
        };
        self.send_relay_cell(cell).await?;

        let Some(conflux_handler) = self.conflux_handler.as_mut() else {
            return Err(internal!("ConfluxMsgHandler disappeared?!").into());
        };

        Ok(conflux_handler.note_link_sent(runtime.wallclock())?)
    }

    /// Get the wallclock time when the handshake on this circuit is supposed to time out.
    ///
    /// Returns `None` if the handshake is not currently in progress.
    pub(super) fn conflux_hs_timeout(&self) -> Option<SystemTime> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                self.conflux_handler.as_ref().map(|handler| handler.handshake_timeout())?
            } else {
                None
            }
        }
    }

    /// Handle a [`CtrlMsg::AddFakeHop`](super::CtrlMsg::AddFakeHop) message.
    #[cfg(test)]
    pub(super) fn handle_add_fake_hop(
        &mut self,
        format: RelayCellFormat,
        fwd_lasthop: bool,
        rev_lasthop: bool,
        dummy_peer_id: path::HopDetail,
        // TODO-CGO: Take HopSettings instead of CircParams.
        // (Do this after we've got the virtual-hop refactorings done for
        // virtual extending.)
        params: &crate::client::circuit::CircParameters,
        done: ReactorResultChannel<()>,
    ) {
        use tor_protover::{Protocols, named};

        use crate::client::circuit::test::DummyCrypto;

        assert!(matches!(format, RelayCellFormat::V0));
        let _ = format; // TODO-CGO: remove this once we have CGO+hs implemented.

        let fwd = Box::new(DummyCrypto::new(fwd_lasthop));
        let rev = Box::new(DummyCrypto::new(rev_lasthop));
        let binding = None;

        let settings = HopSettings::from_params_and_caps(
            // This is for testing only, so we'll assume full negotiation took place.
            crate::circuit::circhop::HopNegotiationType::Full,
            params,
            &[named::FLOWCTRL_CC].into_iter().collect::<Protocols>(),
        )
        .expect("Can't construct HopSettings");
        self.add_hop(dummy_peer_id, fwd, rev, binding, &settings)
            .expect("could not add hop to circuit");
        let _ = done.send(Ok(()));
    }

    /// Encode `msg` and encrypt it, returning the resulting cell
    /// and tag that should be expected for an authenticated SENDME sent
    /// in response to that cell.
    fn encode_relay_cell(
        crypto_out: &mut OutboundClientCrypt,
        relay_format: RelayCellFormat,
        hop: HopNum,
        early: bool,
        msg: AnyRelayMsgOuter,
    ) -> Result<(AnyChanMsg, SendmeTag)> {
        let mut body: RelayCellBody = msg
            .encode(relay_format, &mut rand::rng())
            .map_err(|e| Error::from_cell_enc(e, "relay cell body"))?
            .into();
        let cmd = if early {
            ChanCmd::RELAY_EARLY
        } else {
            ChanCmd::RELAY
        };
        let tag = crypto_out.encrypt(cmd, &mut body, hop)?;
        let msg = Relay::from(BoxedCellBody::from(body));
        let msg = if early {
            AnyChanMsg::RelayEarly(msg.into())
        } else {
            AnyChanMsg::Relay(msg)
        };

        Ok((msg, tag))
    }

    /// Encode `msg`, encrypt it, and send it to the 'hop'th hop.
    ///
    /// If there is insufficient outgoing *circuit-level* or *stream-level*
    /// SENDME window, an error is returned instead.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    ///
    /// NOTE: the reactor should not call this function directly, only via
    /// [`ConfluxSet::send_relay_cell_on_leg`](super::conflux::ConfluxSet::send_relay_cell_on_leg),
    /// which will reroute the message, if necessary to the primary leg.
    pub(super) async fn send_relay_cell(&mut self, msg: SendRelayCell) -> Result<()> {
        self.send_relay_cell_inner(msg, None).await
    }

    /// As [`send_relay_cell`](Self::send_relay_cell), but takes an optional
    /// [`QueuedCellPaddingInfo`] in `padding_info`.
    ///
    /// If `padding_info` is None, `msg` must be non-padding: we report it as such to the
    /// padding controller.
    async fn send_relay_cell_inner(
        &mut self,
        msg: SendRelayCell,
        padding_info: Option<QueuedCellPaddingInfo>,
    ) -> Result<()> {
        let SendRelayCell {
            hop,
            early,
            cell: msg,
        } = msg;

        let is_conflux_link = msg.cmd() == RelayCmd::CONFLUX_LINK;
        if !is_conflux_link && self.is_conflux_pending() {
            // Note: it is the responsibility of the reactor user to wait until
            // at least one of the legs completes the handshake.
            return Err(internal!("tried to send cell on unlinked circuit").into());
        }

        trace!(circ_id = %self.unique_id, cell = ?msg, "sending relay cell");

        // Cloned, because we borrow mutably from self when we get the circhop.
        let runtime = self.runtime.clone();
        let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());
        let stream_id = msg.stream_id();
        let hop = hop.expect("missing hop in client SendRelayCell?!");
        let circhop = self.hops.get_mut(hop).ok_or(Error::NoSuchHop)?;

        // We might be out of capacity entirely; see if we are about to hit a limit.
        //
        // TODO: If we ever add a notion of _recoverable_ errors below, we'll
        // need a way to restore this limit, and similarly for about_to_send().
        circhop.decrement_outbound_cell_limit()?;

        // We need to apply stream-level flow control *before* encoding the message.
        if c_t_w {
            if let Some(stream_id) = stream_id {
                circhop.about_to_send(stream_id, msg.msg())?;
            }
        }

        // Save the RelayCmd of the message before it gets consumed below.
        // We need this to tell our ConfluxMsgHandler about the cell we've just sent,
        // so that it can update its counters.
        let relay_cmd = msg.cmd();

        // NOTE(eta): Now that we've encrypted the cell, we *must* either send it or abort
        //            the whole circuit (e.g. by returning an error).
        let (msg, tag) = Self::encode_relay_cell(
            &mut self.crypto_out,
            circhop.relay_cell_format(),
            hop,
            early,
            msg,
        )?;
        // The cell counted for congestion control, inform our algorithm of such and pass down the
        // tag for authenticated SENDMEs.
        if c_t_w {
            circhop.ccontrol().note_data_sent(&runtime, &tag)?;
        }

        // Remember that we've enqueued this cell.
        let padding_info = padding_info.or_else(|| self.padding_ctrl.queued_data(hop));

        self.send_msg(msg, padding_info).await?;

        #[cfg(feature = "conflux")]
        if let Some(conflux) = self.conflux_handler.as_mut() {
            conflux.note_cell_sent(relay_cmd);
        }

        Ok(())
    }

    /// Helper: process a cell on a channel.  Most cells get ignored
    /// or rejected; a few get delivered to circuits.
    ///
    /// Return `CellStatus::CleanShutdown` if we should exit.
    ///
    // TODO: returning `Vec<CircuitCmd>` means we're unnecessarily
    // allocating a `Vec` here. Generally, the number of commands is going to be small
    // (usually 1, but > 1 when we start supporting packed cells).
    //
    // We should consider using smallvec instead. It might also be a good idea to have a
    // separate higher-level type splitting this out into Single(CircuitCmd),
    // and Multiple(SmallVec<[CircuitCmd; <capacity>]>).
    pub(super) fn handle_cell(
        &mut self,
        handlers: &mut CellHandlers,
        leg: UniqId,
        cell: ClientCircChanMsg,
    ) -> Result<Vec<CircuitCmd>> {
        trace!(circ_id = %self.unique_id, cell = ?cell, "handling cell");
        use ClientCircChanMsg::*;
        match cell {
            Relay(r) => self.handle_relay_cell(handlers, leg, r),
            Destroy(d) => {
                let reason = d.reason();
                debug!(
                    circ_id = %self.unique_id,
                    "Received DESTROY cell. Reason: {} [{}]",
                    reason.human_str(),
                    reason
                );

                self.handle_destroy_cell().map(|c| vec![c])
            }
        }
    }

    /// Decode `cell`, returning its corresponding hop number, tag,
    /// and decoded body.
    fn decode_relay_cell(
        &mut self,
        cell: Relay,
    ) -> Result<(HopNum, SendmeTag, RelayCellDecoderResult)> {
        // This is always RELAY, not RELAY_EARLY, so long as this code is client-only.
        let cmd = cell.cmd();
        let mut body = cell.into_relay_body().into();

        // Decrypt the cell. If it's recognized, then find the
        // corresponding hop.
        let (hopnum, tag) = self.crypto_in.decrypt(cmd, &mut body)?;

        // Decode the cell.
        let decode_res = self
            .hop_mut(hopnum)
            .ok_or_else(|| {
                Error::from(internal!(
                    "Trying to decode cell from nonexistent hop {:?}",
                    hopnum
                ))
            })?
            .decode(body.into())?;

        Ok((hopnum, tag, decode_res))
    }

    /// React to a Relay or RelayEarly cell.
    fn handle_relay_cell(
        &mut self,
        handlers: &mut CellHandlers,
        leg: UniqId,
        cell: Relay,
    ) -> Result<Vec<CircuitCmd>> {
        let (hopnum, tag, decode_res) = self.decode_relay_cell(cell)?;

        if decode_res.is_padding() {
            self.padding_ctrl.decrypted_padding(hopnum)?;
        } else {
            self.padding_ctrl.decrypted_data(hopnum);
        }

        // Check whether we are allowed to receive more data for this circuit hop.
        self.hop_mut(hopnum)
            .ok_or_else(|| internal!("nonexistent hop {:?}", hopnum))?
            .decrement_inbound_cell_limit()?;

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            self.hop_mut(hopnum)
                .ok_or_else(|| Error::CircProto("Sendme from nonexistent hop".into()))?
                .ccontrol()
                .note_data_received()?
        } else {
            false
        };

        let mut circ_cmds = vec![];
        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let sendme = Sendme::from(tag);
            let cell = AnyRelayMsgOuter::new(None, sendme.into());
            circ_cmds.push(CircuitCmd::Send(SendRelayCell {
                hop: Some(hopnum),
                early: false,
                cell,
            }));

            // Inform congestion control of the SENDME we are sending. This is a circuit level one.
            self.hop_mut(hopnum)
                .ok_or_else(|| {
                    Error::from(internal!(
                        "Trying to send SENDME to nonexistent hop {:?}",
                        hopnum
                    ))
                })?
                .ccontrol()
                .note_sendme_sent()?;
        }

        let (mut msgs, incomplete) = decode_res.into_parts();
        while let Some(msg) = msgs.next() {
            let msg_status = self.handle_relay_msg(handlers, hopnum, leg, c_t_w, msg)?;

            match msg_status {
                None => continue,
                Some(msg @ CircuitCmd::CleanShutdown) => {
                    for m in msgs {
                        debug!(
                            "{id}: Ignoring relay msg received after triggering shutdown: {m:?}",
                            id = self.unique_id
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!(
                            "{id}: Ignoring partial relay msg received after triggering shutdown: {:?}",
                            incomplete,
                            id = self.unique_id,
                        );
                    }
                    circ_cmds.push(msg);
                    return Ok(circ_cmds);
                }
                Some(msg) => {
                    circ_cmds.push(msg);
                }
            }
        }

        Ok(circ_cmds)
    }

    /// Handle a single incoming relay message.
    fn handle_relay_msg(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        leg: UniqId,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(streamid) = streamid else {
            return self.handle_meta_cell(handlers, hopnum, msg);
        };

        #[cfg(feature = "conflux")]
        let msg = if let Some(conflux) = self.conflux_handler.as_mut() {
            match conflux.action_for_msg(hopnum, cell_counts_toward_windows, streamid, msg)? {
                ConfluxAction::Deliver(msg) => {
                    // The message either doesn't count towards the sequence numbers
                    // or is already well-ordered, so we're ready to handle it.

                    // It's possible that some of our buffered messages are now ready to be
                    // handled. We don't check that here, however, because that's handled
                    // by the reactor main loop.
                    msg
                }
                ConfluxAction::Enqueue(msg) => {
                    // Tell the reactor to enqueue this msg
                    return Ok(Some(CircuitCmd::Enqueue(msg)));
                }
            }
        } else {
            // If we don't have a conflux_handler, it means this circuit is not part of
            // a conflux tunnel, so we can just process the message.
            msg
        };

        self.handle_in_order_relay_msg(
            handlers,
            hopnum,
            leg,
            cell_counts_toward_windows,
            streamid,
            msg,
        )
    }

    /// Handle a single incoming relay message that is known to be in order.
    pub(super) fn handle_in_order_relay_msg(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        leg: UniqId,
        cell_counts_toward_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        let now = self.runtime.now();

        #[cfg(feature = "conflux")]
        if let Some(conflux) = self.conflux_handler.as_mut() {
            conflux.inc_last_seq_delivered(&msg);
        }

        let path = self.mutable.path();

        let nonexistent_hop_err = || Error::CircProto("Cell from nonexistent hop!".into());
        let hop = self.hop_mut(hopnum).ok_or_else(nonexistent_hop_err)?;

        let hop_detail = path
            .iter()
            .nth(usize::from(hopnum))
            .ok_or_else(nonexistent_hop_err)?;

        // Returns the original message if it's an incoming stream request
        // that we need to handle.
        let res = hop.handle_msg(hop_detail, cell_counts_toward_windows, streamid, msg, now)?;

        // If it was an incoming stream request, we don't need to worry about
        // sending an XOFF as there's no stream data within this message.
        if let Some(msg) = res {
            cfg_if::cfg_if! {
                if #[cfg(feature = "hs-service")] {
                    return self.handle_incoming_stream_request(handlers, msg, streamid, hopnum, leg);
                } else {
                    return Err(internal!("incoming stream not rejected, but hs-service feature is disabled?!").into());
                }
            }
        }

        // We may want to send an XOFF if the incoming buffer is too large.
        if let Some(cell) = hop.maybe_send_xoff(streamid)? {
            let cell = AnyRelayMsgOuter::new(Some(streamid), cell.into());
            let cell = SendRelayCell {
                hop: Some(hopnum),
                early: false,
                cell,
            };
            return Ok(Some(CircuitCmd::Send(cell)));
        }

        Ok(None)
    }

    /// Handle a conflux message coming from the specified hop.
    ///
    /// Returns an error if
    ///
    ///   * this is not a conflux circuit (i.e. it doesn't have a [`ConfluxMsgHandler`])
    ///   * this is a client circuit and the conflux message originated an unexpected hop
    ///   * the cell was sent in violation of the handshake protocol
    #[cfg(feature = "conflux")]
    fn handle_conflux_msg(
        &mut self,
        hop: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<ConfluxCmd>> {
        let Some(conflux_handler) = self.conflux_handler.as_mut() else {
            // If conflux is not enabled, tear down the circuit
            // (see 4.2.1. Cell Injection Side Channel Mitigations in prop329)
            return Err(Error::CircProto(format!(
                "Received {} cell from hop {} on non-conflux client circuit?!",
                msg.cmd(),
                hop.display(),
            )));
        };

        Ok(conflux_handler.handle_conflux_msg(msg, hop))
    }

    /// For conflux: return the sequence number of the last cell sent on this leg.
    ///
    /// Returns an error if this circuit is not part of a conflux set.
    #[cfg(feature = "conflux")]
    pub(super) fn last_seq_sent(&self) -> Result<u64> {
        let handler = self
            .conflux_handler
            .as_ref()
            .ok_or_else(|| internal!("tried to get last_seq_sent of non-conflux circ"))?;

        Ok(handler.last_seq_sent())
    }

    /// For conflux: set the sequence number of the last cell sent on this leg.
    ///
    /// Returns an error if this circuit is not part of a conflux set.
    #[cfg(feature = "conflux")]
    pub(super) fn set_last_seq_sent(&mut self, n: u64) -> Result<()> {
        let handler = self
            .conflux_handler
            .as_mut()
            .ok_or_else(|| internal!("tried to get last_seq_sent of non-conflux circ"))?;

        handler.set_last_seq_sent(n);
        Ok(())
    }

    /// For conflux: return the sequence number of the last cell received on this leg.
    ///
    /// Returns an error if this circuit is not part of a conflux set.
    #[cfg(feature = "conflux")]
    pub(super) fn last_seq_recv(&self) -> Result<u64> {
        let handler = self
            .conflux_handler
            .as_ref()
            .ok_or_else(|| internal!("tried to get last_seq_recv of non-conflux circ"))?;

        Ok(handler.last_seq_recv())
    }

    /// A helper for handling incoming stream requests.
    ///
    // TODO: can we make this a method on CircHop to avoid the double HopNum lookup?
    #[cfg(feature = "hs-service")]
    fn handle_incoming_stream_request(
        &mut self,
        handlers: &mut CellHandlers,
        msg: UnparsedRelayMsg,
        stream_id: StreamId,
        hop_num: HopNum,
        leg: UniqId,
    ) -> Result<Option<CircuitCmd>> {
        use super::syncview::ClientCircSyncView;
        use tor_cell::relaycell::msg::EndReason;
        use tor_error::into_internal;
        use tor_log_ratelim::log_ratelim;

        use crate::client::{circuit::CIRCUIT_BUFFER_SIZE, reactor::StreamReqInfo};

        // We need to construct this early so that we don't double-borrow &mut self

        let Some(handler) = handlers.incoming_stream_req_handler.as_mut() else {
            return Err(Error::CircProto(
                "Cannot handle BEGIN cells on this circuit".into(),
            ));
        };

        if hop_num != handler.hop_num {
            return Err(Error::CircProto(format!(
                "Expecting incoming streams from {}, but received {} cell from unexpected hop {}",
                handler.hop_num.display(),
                msg.cmd(),
                hop_num.display()
            )));
        }

        let message_closes_stream = handler.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        // TODO: we've already looked up the `hop` in handle_relay_cell, so we shouldn't
        // have to look it up again! However, we can't pass the `&mut hop` reference from
        // `handle_relay_cell` to this function, because that makes Rust angry (we'd be
        // borrowing self as mutable more than once).
        //
        // TODO: we _could_ use self.hops.get_mut(..) instead self.hop_mut(..) inside
        // handle_relay_cell to work around the problem described above
        let hop = self.hops.get_mut(hop_num).ok_or(Error::CircuitClosed)?;

        if message_closes_stream {
            hop.ending_msg_received(stream_id)?;

            return Ok(None);
        }

        let begin = msg
            .decode::<Begin>()
            .map_err(|e| Error::from_bytes_err(e, "Invalid Begin message"))?
            .into_msg();

        let req = IncomingStreamRequest::Begin(begin);

        {
            use crate::client::stream::IncomingStreamRequestDisposition::*;

            let ctx = crate::client::stream::IncomingStreamRequestContext { request: &req };
            // IMPORTANT: ClientCircSyncView::n_open_streams() (called via disposition() below)
            // accesses the stream map mutexes!
            //
            // This means it's very important not to call this function while any of the hop's
            // stream map mutex is held.
            let view = CircSyncView::new_client(ClientCircSyncView::new(&self.hops));

            match handler.filter.as_mut().disposition(&ctx, &view)? {
                Accept => {}
                CloseCircuit => return Ok(Some(CircuitCmd::CleanShutdown)),
                RejectRequest(end) => {
                    let end_msg = AnyRelayMsgOuter::new(Some(stream_id), end.into());
                    let cell = SendRelayCell {
                        hop: Some(hop_num),
                        early: false,
                        cell: end_msg,
                    };
                    return Ok(Some(CircuitCmd::Send(cell)));
                }
            }
        }

        // TODO: Sadly, we need to look up `&mut hop` yet again,
        // since we needed to pass `&self.hops` by reference to our filter above. :(
        let hop = self.hops.get_mut(hop_num).ok_or(Error::CircuitClosed)?;
        let relay_cell_format = hop.relay_cell_format();

        let memquota = StreamAccount::new(&self.memquota)?;

        let (sender, receiver) = stream_queue(
            #[cfg(not(feature = "flowctl-cc"))]
            STREAM_READER_BUFFER,
            &memquota,
            self.chan_sender.time_provider(),
        )?;

        let (msg_tx, msg_rx) = MpscSpec::new(CIRCUIT_BUFFER_SIZE).new_mq(
            self.chan_sender.time_provider().clone(),
            memquota.as_raw_account(),
        )?;

        let (rate_limit_tx, rate_limit_rx) = watch::channel_with(StreamRateLimit::MAX);

        // A channel for the reactor to request a new drain rate from the reader.
        // Typically this notification will be sent after an XOFF is sent so that the reader can
        // send us a new drain rate when the stream data queue becomes empty.
        let mut drain_rate_request_tx = NotifySender::new_typed();
        let drain_rate_request_rx = drain_rate_request_tx.subscribe();

        let cmd_checker = InboundDataCmdChecker::new_connected();
        hop.add_ent_with_id(
            sender,
            msg_rx,
            rate_limit_tx,
            drain_rate_request_tx,
            stream_id,
            cmd_checker,
        )?;

        let outcome = Pin::new(&mut handler.incoming_sender).try_send(StreamReqInfo {
            req,
            stream_id,
            hop: (leg, hop_num).into(),
            msg_tx,
            receiver,
            rate_limit_stream: rate_limit_rx,
            drain_rate_request_stream: drain_rate_request_rx,
            memquota,
            relay_cell_format,
        });

        log_ratelim!("Delivering message to incoming stream handler"; outcome);

        if let Err(e) = outcome {
            if e.is_full() {
                // The IncomingStreamRequestHandler's stream is full; it isn't
                // handling requests fast enough. So instead, we reply with an
                // END cell.
                let end_msg = AnyRelayMsgOuter::new(
                    Some(stream_id),
                    End::new_with_reason(EndReason::RESOURCELIMIT).into(),
                );

                let cell = SendRelayCell {
                    hop: Some(hop_num),
                    early: false,
                    cell: end_msg,
                };
                return Ok(Some(CircuitCmd::Send(cell)));
            } else if e.is_disconnected() {
                // The IncomingStreamRequestHandler's stream has been dropped.
                // In the Tor protocol as it stands, this always means that the
                // circuit itself is out-of-use and should be closed. (See notes
                // on `allow_stream_requests.`)
                //
                // Note that we will _not_ reach this point immediately after
                // the IncomingStreamRequestHandler is dropped; we won't hit it
                // until we next get an incoming request.  Thus, if we do later
                // want to add early detection for a dropped
                // IncomingStreamRequestHandler, we need to do it elsewhere, in
                // a different way.
                debug!(
                    circ_id = %self.unique_id,
                    "Incoming stream request receiver dropped",
                );
                // This will _cause_ the circuit to get closed.
                return Err(Error::CircuitClosed);
            } else {
                // There are no errors like this with the current design of
                // futures::mpsc, but we shouldn't just ignore the possibility
                // that they'll be added later.
                return Err(Error::from((into_internal!(
                    "try_send failed unexpectedly"
                ))(e)));
            }
        }

        Ok(None)
    }

    /// Helper: process a destroy cell.
    #[allow(clippy::unnecessary_wraps)]
    fn handle_destroy_cell(&mut self) -> Result<CircuitCmd> {
        // I think there is nothing more to do here.
        Ok(CircuitCmd::CleanShutdown)
    }

    /// Handle a [`CtrlMsg::Create`](super::CtrlMsg::Create) message.
    pub(super) async fn handle_create(
        &mut self,
        recv_created: oneshot::Receiver<CreateResponse>,
        handshake: CircuitHandshake,
        settings: HopSettings,
        done: ReactorResultChannel<()>,
    ) -> StdResult<(), ReactorError> {
        let ret = match handshake {
            CircuitHandshake::CreateFast => self.create_firsthop_fast(recv_created, settings).await,
            CircuitHandshake::Ntor {
                public_key,
                ed_identity,
            } => {
                self.create_firsthop_ntor(recv_created, ed_identity, public_key, settings)
                    .await
            }
            CircuitHandshake::NtorV3 { public_key } => {
                self.create_firsthop_ntor_v3(recv_created, public_key, settings)
                    .await
            }
        };
        let _ = done.send(ret); // don't care if sender goes away

        // TODO: maybe we don't need to flush here?
        // (we could let run_once() handle all the flushing)
        self.chan_sender.flush().await?;

        Ok(())
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, and a handshake object to perform
    /// the cryptographic handshake.
    async fn create_impl<H, W, M>(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        wrap: &W,
        key: &H::KeyType,
        mut settings: HopSettings,
        msg: &M,
    ) -> Result<()>
    where
        H: ClientHandshake + HandshakeAuxDataHandler,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
        M: Borrow<H::ClientAuxData>,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let (state, msg) = {
            // done like this because holding the RNG across an await boundary makes the future
            // non-Send
            let mut rng = rand::rng();
            H::client1(&mut rng, key, msg)?
        };
        let create_cell = wrap.to_chanmsg(msg);
        trace!(
            circ_id = %self.unique_id,
            create = %create_cell.cmd(),
            "Extending to hop 1",
        );
        self.send_msg(create_cell, None).await?;

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let relay_handshake = wrap.decode_chanmsg(reply)?;
        let (server_msg, keygen) = H::client2(state, relay_handshake)?;

        H::handle_server_aux_data(&mut settings, &server_msg)?;

        let BoxedClientLayer { fwd, back, binding } = settings
            .relay_crypt_protocol()
            .construct_client_layers(HandshakeRole::Initiator, keygen)?;

        trace!(circ_id = %self.unique_id, "Handshake complete; circuit created.");

        let peer_id = self.channel.target().clone();

        self.add_hop(
            path::HopDetail::Relay(peer_id),
            fwd,
            back,
            binding,
            &settings,
        )?;
        Ok(())
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CREATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    async fn create_firsthop_fast(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        settings: HopSettings,
    ) -> Result<()> {
        // In a CREATE_FAST handshake, we can't negotiate a format other than this.
        let wrap = CreateFastWrap;
        self.create_impl::<CreateFastClient, _, _>(recvcreated, &wrap, &(), settings, &())
            .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided keys must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        ed_identity: pk::ed25519::Ed25519Identity,
        pubkey: NtorPublicKey,
        settings: HopSettings,
    ) -> Result<()> {
        // Exit now if we have an Ed25519 or RSA identity mismatch.
        let target = RelayIds::builder()
            .ed_identity(ed_identity)
            .rsa_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR,
        };
        self.create_impl::<NtorClient, _, _>(recvcreated, &wrap, &pubkey, settings, &())
            .await
    }

    /// Use the ntor-v3 handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided key must match the channel's target,
    /// or the handshake will fail.
    async fn create_firsthop_ntor_v3(
        &mut self,
        recvcreated: oneshot::Receiver<CreateResponse>,
        pubkey: NtorV3PublicKey,
        settings: HopSettings,
    ) -> Result<()> {
        // Exit now if we have a mismatched key.
        let target = RelayIds::builder()
            .ed_identity(pubkey.id)
            .build()
            .expect("Unable to build RelayIds");
        self.channel.check_match(&target)?;

        // Set the client extensions.
        let client_extensions = settings.circuit_request_extensions()?;
        let wrap = Create2Wrap {
            handshake_type: HandshakeType::NTOR_V3,
        };

        self.create_impl::<NtorV3Client, _, _>(
            recvcreated,
            &wrap,
            &pubkey,
            settings,
            &client_extensions,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    ///
    /// Will return an error if the circuit already has [`u8::MAX`] hops.
    pub(super) fn add_hop(
        &mut self,
        peer_id: path::HopDetail,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        binding: Option<CircuitBinding>,
        settings: &HopSettings,
    ) -> StdResult<(), Bug> {
        let hop_num = self.hops.len();
        debug_assert_eq!(hop_num, usize::from(self.num_hops()));

        // There are several places in the code that assume that a `usize` hop number
        // can be cast or converted to a `u8` hop number,
        // so this check is important to prevent panics or incorrect behaviour.
        if hop_num == usize::from(u8::MAX) {
            return Err(internal!(
                "cannot add more hops to a circuit with `u8::MAX` hops"
            ));
        }

        let hop_num = (hop_num as u8).into();

        let hop = CircHop::new(self.unique_id, hop_num, settings);
        self.hops.push(hop);
        self.crypto_in.add_layer(rev);
        self.crypto_out.add_layer(fwd);
        self.mutable.add_hop(peer_id, binding);

        Ok(())
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    ///
    /// NOTE(prop349): this is part of Arti's "Base Circuit Hop Handler".
    /// This function returns a `CircProto` error if `msg` is an unsupported,
    /// unexpected, or otherwise invalid message:
    ///
    ///   * unexpected messages are rejected by returning an error using
    ///     [`unsupported_client_cell`]
    ///   * SENDME/TRUNCATED messages are rejected if they don't parse
    ///   * SENDME authentication tags are validated inside [`Circuit::handle_sendme`]
    ///   * conflux cells are handled in the client [`ConfluxMsgHandler`]
    ///
    /// The error is propagated all the way up to [`Circuit::handle_cell`],
    /// and eventually ends up being returned from the reactor's `run_once` function,
    /// causing it to shut down.
    #[allow(clippy::cognitive_complexity)]
    fn handle_meta_cell(
        &mut self,
        handlers: &mut CellHandlers,
        hopnum: HopNum,
        msg: UnparsedRelayMsg,
    ) -> Result<Option<CircuitCmd>> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.

        // TODO: This pattern (Check command, try to decode, map error) occurs
        // several times, and would be good to extract simplify. Such
        // simplification is obstructed by a couple of factors: First, that
        // there is not currently a good way to get the RelayCmd from _type_ of
        // a RelayMsg.  Second, that decode() [correctly] consumes the
        // UnparsedRelayMsg.  I tried a macro-based approach, and didn't care
        // for it. -nickm
        if msg.cmd() == RelayCmd::SENDME {
            let sendme = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "sendme message"))?
                .into_msg();

            return Ok(Some(CircuitCmd::HandleSendMe {
                hop: hopnum,
                sendme,
            }));
        }
        if msg.cmd() == RelayCmd::TRUNCATED {
            let truncated = msg
                .decode::<Truncated>()
                .map_err(|e| Error::from_bytes_err(e, "truncated message"))?
                .into_msg();
            let reason = truncated.reason();
            debug!(
                circ_id = %self.unique_id,
                "Truncated from hop {}. Reason: {} [{}]",
                hopnum.display(),
                reason.human_str(),
                reason
            );

            return Ok(Some(CircuitCmd::CleanShutdown));
        }

        if msg.cmd() == RelayCmd::DROP {
            cfg_if::cfg_if! {
                if #[cfg(feature = "circ-padding")] {
                    return Ok(None);
                } else {
                    use crate::util::err::ExcessPadding;
                    return Err(Error::ExcessPadding(ExcessPadding::NoPaddingNegotiated, hopnum));
                }
            }
        }

        trace!(circ_id = %self.unique_id, cell = ?msg, "Received meta-cell");

        #[cfg(feature = "conflux")]
        if matches!(
            msg.cmd(),
            RelayCmd::CONFLUX_LINK
                | RelayCmd::CONFLUX_LINKED
                | RelayCmd::CONFLUX_LINKED_ACK
                | RelayCmd::CONFLUX_SWITCH
        ) {
            let cmd = self.handle_conflux_msg(hopnum, msg)?;
            return Ok(cmd.map(CircuitCmd::from));
        }

        if self.is_conflux_pending() {
            warn!(
                circ_id = %self.unique_id,
                "received unexpected cell {msg:?} on unlinked conflux circuit",
            );
            return Err(Error::CircProto(
                "Received unexpected cell on unlinked circuit".into(),
            ));
        }

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: should the conflux state machine be a meta cell handler?
        // We'd need to add support for multiple meta handlers, and change the
        // MetaCellHandler API to support returning Option<RunOnceCmdInner>
        // (because some cells will require sending a response)
        if let Some(mut handler) = handlers.meta_handler.take() {
            // The handler has a TargetHop so we do a quick convert for equality check.
            if handler.expected_hop() == (self.unique_id(), hopnum).into() {
                // Somebody was waiting for a message -- maybe this message
                let ret = handler.handle_msg(msg, self);
                trace!(
                    circ_id = %self.unique_id,
                    result = ?ret,
                    "meta handler completed",
                );
                match ret {
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::Consumed) => {
                        handlers.meta_handler = Some(handler);
                        Ok(None)
                    }
                    Ok(MetaCellDisposition::ConversationFinished) => Ok(None),
                    #[cfg(feature = "send-control-msg")]
                    Ok(MetaCellDisposition::CloseCirc) => Ok(Some(CircuitCmd::CleanShutdown)),
                    Err(e) => Err(e),
                }
            } else {
                // Somebody wanted a message from a different hop!  Put this
                // one back.
                handlers.meta_handler = Some(handler);

                unsupported_client_cell!(msg, hopnum)
            }
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            unsupported_client_cell!(msg)
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    pub(super) fn handle_sendme(
        &mut self,
        hopnum: HopNum,
        msg: Sendme,
        signals: CongestionSignals,
    ) -> Result<Option<CircuitCmd>> {
        // Cloned, because we borrow mutably from self when we get the circhop.
        let runtime = self.runtime.clone();

        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find hop {}", hopnum.display())))?;

        let tag = msg.into_sendme_tag().ok_or_else(||
                // Versions of Tor <=0.3.5 would omit a SENDME tag in this case;
                // but we don't support those any longer.
                 Error::CircProto("missing tag on circuit sendme".into()))?;
        // Update the CC object that we received a SENDME along with possible congestion signals.
        hop.ccontrol()
            .note_sendme_received(&runtime, tag, signals)?;
        Ok(None)
    }

    /// Send a message onto the circuit's channel.
    ///
    /// If the channel is ready to accept messages, it will be sent immediately. If not, the message
    /// will be enqueued for sending at a later iteration of the reactor loop.
    ///
    /// `info` is the status returned from the padding controller when we told it we were queueing
    /// this data.  It should be provided whenever possible.
    ///
    /// # Note
    ///
    /// Making use of the enqueuing capabilities of this function is discouraged! You should first
    /// check whether the channel is ready to receive messages (`self.channel.poll_ready`), and
    /// ideally use this to implement backpressure (such that you do not read from other sources
    /// that would send here while you know you're unable to forward the messages on).
    async fn send_msg(
        &mut self,
        msg: AnyChanMsg,
        info: Option<QueuedCellPaddingInfo>,
    ) -> Result<()> {
        let cell = AnyChanCell::new(Some(self.channel_id), msg);
        // Note: this future is always `Ready`, so await won't block.
        Pin::new(&mut self.chan_sender)
            .send_unbounded((cell, info))
            .await?;
        Ok(())
    }

    /// Remove all halfstreams that are expired at `now`.
    pub(super) fn remove_expired_halfstreams(&mut self, now: Instant) {
        self.hops.remove_expired_halfstreams(now);
    }

    /// Return a reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn hop(&self, hopnum: HopNum) -> Option<&CircHop> {
        self.hops.hop(hopnum)
    }

    /// Return a mutable reference to the hop corresponding to `hopnum`, if there is one.
    pub(super) fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(hopnum)
    }

    /// Begin a stream with the provided hop in this circuit.
    // TODO: see if there's a way that we can clean this up
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_stream(
        &mut self,
        hop_num: HopNum,
        message: AnyRelayMsg,
        sender: StreamQueueSender,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        rate_limit_notifier: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
        cmd_checker: AnyCmdChecker,
    ) -> StdResult<Result<(SendRelayCell, StreamId)>, Bug> {
        let Some(hop) = self.hop_mut(hop_num) else {
            return Err(internal!(
                "{}: Attempting to send a BEGIN cell to an unknown hop {hop_num:?}",
                self.unique_id,
            ));
        };

        Ok(hop.begin_stream(
            message,
            sender,
            rx,
            rate_limit_notifier,
            drain_rate_requester,
            cmd_checker,
        ))
    }

    /// Close the specified stream
    pub(super) async fn close_stream(
        &mut self,
        hop_num: HopNum,
        sid: StreamId,
        behav: CloseStreamBehavior,
        reason: streammap::TerminateReason,
        expiry: Instant,
    ) -> Result<()> {
        if let Some(hop) = self.hop_mut(hop_num) {
            let res = hop.close_stream(sid, behav, reason, expiry)?;
            if let Some(cell) = res {
                self.send_relay_cell(cell).await?;
            }
        }
        Ok(())
    }

    /// Returns true if there are any streams on this circuit
    ///
    /// Important: this function locks the stream map of its each of the [`CircHop`]s
    /// in this circuit, so it must **not** be called from any function where the
    /// stream map lock is held.
    pub(super) fn has_streams(&self) -> bool {
        self.hops.has_streams()
    }

    /// The number of hops in this circuit.
    pub(super) fn num_hops(&self) -> u8 {
        // `Circuit::add_hop` checks to make sure that we never have more than `u8::MAX` hops,
        // so `self.hops.len()` should be safe to cast to a `u8`.
        // If that assumption is violated,
        // we choose to panic rather than silently use the wrong hop due to an `as` cast.
        self.hops
            .len()
            .try_into()
            .expect("`hops.len()` has more than `u8::MAX` hops")
    }

    /// Check whether this circuit has any hops.
    pub(super) fn has_hops(&self) -> bool {
        !self.hops.is_empty()
    }

    /// Get the `HopNum` of the last hop, if this circuit is non-empty.
    ///
    /// Returns `None` if the circuit has no hops.
    pub(super) fn last_hop_num(&self) -> Option<HopNum> {
        let num_hops = self.num_hops();
        if num_hops == 0 {
            // asked for the last hop, but there are no hops
            return None;
        }
        Some(HopNum::from(num_hops - 1))
    }

    /// Get the path of the circuit.
    ///
    /// **Warning:** Do not call while already holding the [`Self::mutable`] lock.
    pub(super) fn path(&self) -> Arc<path::Path> {
        self.mutable.path()
    }

    /// Return a ClockSkew declaring how much clock skew the other side of this channel
    /// claimed that we had when we negotiated the connection.
    pub(super) fn clock_skew(&self) -> ClockSkew {
        self.channel.clock_skew()
    }

    /// Does congestion control use stream SENDMEs for the given `hop`?
    ///
    /// Returns `None` if `hop` doesn't exist.
    pub(super) fn uses_stream_sendme(&self, hop: HopNum) -> Option<bool> {
        let hop = self.hop(hop)?;
        Some(hop.ccontrol().uses_stream_sendme())
    }

    /// Returns whether this is a conflux circuit that is not linked yet.
    pub(super) fn is_conflux_pending(&self) -> bool {
        let Some(status) = self.conflux_status() else {
            return false;
        };

        status != ConfluxStatus::Linked
    }

    /// Returns the conflux status of this circuit.
    ///
    /// Returns `None` if this is not a conflux circuit.
    pub(super) fn conflux_status(&self) -> Option<ConfluxStatus> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "conflux")] {
                self.conflux_handler
                    .as_ref()
                    .map(|handler| handler.status())
            } else {
                None
            }
        }
    }

    /// Returns initial RTT on this leg, measured in the conflux handshake.
    #[cfg(feature = "conflux")]
    pub(super) fn init_rtt(&self) -> Option<Duration> {
        self.conflux_handler
            .as_ref()
            .map(|handler| handler.init_rtt())?
    }

    /// Start or stop padding at the given hop.
    ///
    /// Replaces any previous padder at that hop.
    ///
    /// Return an error if that hop doesn't exist.
    #[cfg(feature = "circ-padding-manual")]
    pub(super) fn set_padding_at_hop(
        &self,
        hop: HopNum,
        padder: Option<padding::CircuitPadder>,
    ) -> Result<()> {
        if self.hop(hop).is_none() {
            return Err(Error::NoSuchHop);
        }
        self.padding_ctrl.install_padder_padding_at_hop(hop, padder);
        Ok(())
    }

    /// Determine how exactly to handle a request to handle padding.
    ///
    /// This is fairly complicated; see the maybenot documentation for more information.
    ///
    /// ## Limitations
    ///
    /// In our current padding implementation, a circuit is either blocked or not blocked:
    /// we do not keep track of which hop is actually doing the blocking.
    #[cfg(feature = "circ-padding")]
    fn padding_disposition(&self, send_padding: &padding::SendPadding) -> CircPaddingDisposition {
        use CircPaddingDisposition::*;
        use padding::Bypass::*;
        use padding::Replace::*;

        // If true, and we are trying to send Replaceable padding,
        // we should let any data in the queue count as the queued padding instead,
        // if it is queued for our target hop (or any subsequent hop).
        //
        // TODO circpad: In addition to letting currently-queued data count as padding,
        // maybenot also permits us to send currently pending data from our streams
        // (or from our next hop, if we're a relay).  We don't have that implemented yet.
        //
        // TODO circpad: This will usually be false, since we try not to queue data
        // when there isn't space to write it.  If we someday add internal per-circuit
        // Buffers to chan_sender, this test is more likely to trigger.
        let have_queued_cell_for_hop = self
            .chan_sender
            .have_queued_cell_for_hop_or_later(send_padding.hop);

        match &self.padding_block {
            Some(blocking) if blocking.is_bypassable => {
                match (
                    send_padding.may_replace_with_data(),
                    send_padding.may_bypass_block(),
                ) {
                    (NotReplaceable, DoNotBypass) => QueuePaddingNormally,
                    (NotReplaceable, BypassBlocking) => QueuePaddingAndBypass,
                    (Replaceable, DoNotBypass) => {
                        if have_queued_cell_for_hop {
                            TreatQueuedCellAsPadding
                        } else {
                            QueuePaddingNormally
                        }
                    }
                    (Replaceable, BypassBlocking) => {
                        if have_queued_cell_for_hop {
                            TreatQueuedCellAsPadding
                        } else {
                            QueuePaddingAndBypass
                        }
                    }
                }
            }
            Some(_) | None => match send_padding.may_replace_with_data() {
                Replaceable => {
                    if have_queued_cell_for_hop {
                        TreatQueuedCellAsPadding
                    } else {
                        QueuePaddingNormally
                    }
                }
                NotReplaceable => QueuePaddingNormally,
            },
        }
    }

    /// Handle a request from our padding subsystem to send a padding packet.
    #[cfg(feature = "circ-padding")]
    pub(super) async fn send_padding(&mut self, send_padding: padding::SendPadding) -> Result<()> {
        use CircPaddingDisposition::*;

        let target_hop = send_padding.hop;

        match self.padding_disposition(&send_padding) {
            QueuePaddingNormally => {
                let queue_info = self.padding_ctrl.queued_padding(target_hop, send_padding);
                self.queue_padding_cell_for_hop(target_hop, queue_info)
                    .await?;
            }
            QueuePaddingAndBypass => {
                let queue_info = self.padding_ctrl.queued_padding(target_hop, send_padding);
                self.queue_padding_cell_for_hop(target_hop, queue_info)
                    .await?;
            }
            TreatQueuedCellAsPadding => {
                self.padding_ctrl
                    .replaceable_padding_already_queued(target_hop, send_padding);
            }
        }
        Ok(())
    }

    /// Generate and encrypt a padding cell, and send it to a targeted hop.
    ///
    /// Ignores any padding-based blocking.
    #[cfg(feature = "circ-padding")]
    async fn queue_padding_cell_for_hop(
        &mut self,
        target_hop: HopNum,
        queue_info: Option<QueuedCellPaddingInfo>,
    ) -> Result<()> {
        use tor_cell::relaycell::msg::Drop as DropMsg;
        let msg = SendRelayCell {
            hop: Some(target_hop),
            // TODO circpad: we will probably want padding machines that can send EARLY cells.
            early: false,
            cell: AnyRelayMsgOuter::new(None, DropMsg::default().into()),
        };
        self.send_relay_cell_inner(msg, queue_info).await
    }

    /// Enable padding-based blocking,
    /// or change the rule for padding-based blocking to the one in `block`.
    #[cfg(feature = "circ-padding")]
    pub(super) fn start_blocking_for_padding(&mut self, block: padding::StartBlocking) {
        self.chan_sender.start_blocking();
        self.padding_block = Some(block);
    }

    /// Disable padding-based blocking.
    #[cfg(feature = "circ-padding")]
    pub(super) fn stop_blocking_for_padding(&mut self) {
        self.chan_sender.stop_blocking();
        self.padding_block = None;
    }

    /// The estimated circuit build timeout for a circuit of the specified length.
    pub(super) fn estimate_cbt(&self, length: usize) -> Duration {
        self.timeouts.circuit_build_timeout(length)
    }
}

/// A possible way to handle a request to send padding.
#[derive(Copy, Clone, Debug)]
enum CircPaddingDisposition {
    /// Enqueue the padding normally.
    QueuePaddingNormally,
    /// Enqueue the padding, and allow one cell of data on our outbound queue
    /// to bypass the current block.
    QueuePaddingAndBypass,
    /// Do not take any actual padding action:
    /// existing data on our outbound queue will count as padding.
    TreatQueuedCellAsPadding,
}

/// Return the stream ID of `msg`, if it has one.
///
/// Returns `Ok(None)` if `msg` is a meta cell.
fn msg_streamid(msg: &UnparsedRelayMsg) -> Result<Option<StreamId>> {
    let cmd = msg.cmd();
    let streamid = msg.stream_id();
    if !cmd.accepts_streamid_val(streamid) {
        return Err(Error::CircProto(format!(
            "Invalid stream ID {} for relay command {}",
            sv(StreamId::get_or_zero(streamid)),
            msg.cmd()
        )));
    }

    Ok(streamid)
}

impl Drop for Circuit {
    fn drop(&mut self) {
        let _ = self.channel.close_circuit(self.channel_id);
    }
}
