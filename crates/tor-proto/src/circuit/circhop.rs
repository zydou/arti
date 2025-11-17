//! Module exposing structures relating to a reactor's view of a circuit hop.

// TODO(relay): don't import from the client module
use crate::client::circuit::handshake::RelayCryptLayerProtocol;
use crate::client::reactor::circuit::SEND_WINDOW_INIT;

use crate::ccparams::CongestionControlParams;
use crate::circuit::CircParameters;
use crate::congestion::{CongestionControl, sendme};
use crate::stream::CloseStreamBehavior;
use crate::stream::StreamMpscReceiver;
use crate::stream::cmdcheck::{AnyCmdChecker, StreamStatus};
use crate::stream::flow_ctrl::params::FlowCtrlParameters;
use crate::stream::flow_ctrl::state::{StreamFlowCtrl, StreamRateLimit};
use crate::stream::flow_ctrl::xon_xoff::reader::DrainRateRequest;
use crate::stream::queue::StreamQueueSender;
use crate::streammap::{
    self, EndSentStreamEnt, OpenStreamEnt, ShouldSendEnd, StreamEntMut, StreamMap,
};
use crate::util::notify::NotifySender;
use crate::{Error, HopNum, Result};

use postage::watch;
use safelog::sensitive as sv;
use tracing::{trace, warn};

use tor_cell::chancell::BoxedCellBody;
use tor_cell::relaycell::extend::{CcRequest, CircRequestExt};
use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoder, RelayCellDecoderResult, RelayCellFormat, RelayCmd,
    StreamId, UnparsedRelayMsg,
};
use tor_error::{Bug, internal};
use tor_protover::named;

use std::num::NonZeroU32;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

#[cfg(test)]
use tor_cell::relaycell::msg::SendmeTag;

use cfg_if::cfg_if;

/// Type of negotiation that we'll be performing as we establish a hop.
///
/// Determines what flavor of extensions we can send and receive, which in turn
/// limits the hop settings we can negotiate.
///
// TODO-CGO: This is likely to be refactored when we finally add support for
// HsV3+CGO, which will require refactoring
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum HopNegotiationType {
    /// We're using a handshake in which extension-based negotiation cannot occur.
    None,
    /// We're using the HsV3-ntor handshake, in which the client can send extensions,
    /// but the server cannot.
    ///
    /// As a special case, the default relay encryption protocol is the hsv3
    /// variant of Tor1.
    //
    // We would call this "HalfDuplex" or something, but we do not expect to add
    // any more handshakes of this type.
    HsV3,
    /// We're using a handshake in which both client and relay can send extensions.
    Full,
}

/// The settings we use for single hop of a circuit.
///
/// Unlike [`CircParameters`], this type is crate-internal.
/// We construct it based on our settings from the circuit,
/// and from the hop's actual capabilities.
/// Then, we negotiate with the hop as part of circuit
/// creation/extension to determine the actual settings that will be in use.
/// Finally, we use those settings to construct the negotiated circuit hop.
//
// TODO: Relays should probably derive an instance of this type too, as
// part of the circuit creation handshake.
#[derive(Clone, Debug)]
pub(crate) struct HopSettings {
    /// The negotiated congestion control settings for this hop .
    pub(crate) ccontrol: CongestionControlParams,

    /// Flow control parameters that will be used for streams on this hop.
    pub(crate) flow_ctrl_params: FlowCtrlParameters,

    /// Maximum number of permitted incoming relay cells for this hop.
    pub(crate) n_incoming_cells_permitted: Option<u32>,

    /// Maximum number of permitted outgoing relay cells for this hop.
    pub(crate) n_outgoing_cells_permitted: Option<u32>,

    /// The relay cell encryption algorithm and cell format for this hop.
    relay_crypt_protocol: RelayCryptLayerProtocol,
}

impl HopSettings {
    /// Construct a new `HopSettings` based on `params` (a set of circuit parameters)
    /// and `caps` (a set of protocol capabilities for a circuit target).
    ///
    /// The resulting settings will represent what the client would prefer to negotiate
    /// (determined by `params`),
    /// as modified by what the target relay is believed to support (represented by `caps`).
    ///
    /// This represents the `HopSettings` in a pre-negotiation state:
    /// the circuit negotiation process will modify it.
    #[allow(clippy::unnecessary_wraps)] // likely to become fallible in the future.
    pub(crate) fn from_params_and_caps(
        hoptype: HopNegotiationType,
        params: &CircParameters,
        caps: &tor_protover::Protocols,
    ) -> Result<Self> {
        let mut ccontrol = params.ccontrol.clone();
        match ccontrol.alg() {
            crate::ccparams::Algorithm::FixedWindow(_) => {}
            crate::ccparams::Algorithm::Vegas(_) => {
                // If the target doesn't support FLOWCTRL_CC, we can't use Vegas.
                if !caps.supports_named_subver(named::FLOWCTRL_CC) {
                    ccontrol.use_fallback_alg();
                }
            }
        };
        if hoptype == HopNegotiationType::None {
            ccontrol.use_fallback_alg();
        } else if hoptype == HopNegotiationType::HsV3 {
            // TODO #2037, TODO-CGO: We need a way to send congestion control extensions
            // in this case too.  But since we aren't sending them, we
            // should use the fallback algorithm.
            ccontrol.use_fallback_alg();
        }
        let ccontrol = ccontrol; // drop mut

        // Negotiate CGO if it is supported, if CC is also supported,
        // and if CGO is available on this relay.
        let relay_crypt_protocol = match hoptype {
            HopNegotiationType::None => RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0),
            HopNegotiationType::HsV3 => {
                // TODO-CGO: Support CGO when available.
                cfg_if! {
                    if #[cfg(feature = "hs-common")] {
                        RelayCryptLayerProtocol::HsV3(RelayCellFormat::V0)
                    } else {
                        return Err(
                            tor_error::internal!("Unexpectedly tried to negotiate HsV3 without support!").into(),
                        );
                    }
                }
            }
            HopNegotiationType::Full => {
                cfg_if! {
                    if #[cfg(all(feature = "flowctl-cc", feature = "counter-galois-onion"))] {
                        #[allow(clippy::overly_complex_bool_expr)]
                        if  ccontrol.alg().compatible_with_cgo()
                            && caps.supports_named_subver(named::RELAY_NEGOTIATE_SUBPROTO)
                            && caps.supports_named_subver(named::RELAY_CRYPT_CGO)
                        {
                            RelayCryptLayerProtocol::Cgo
                        } else {
                            RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                        }
                    } else {
                        RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                    }
                }
            }
        };

        Ok(Self {
            ccontrol,
            flow_ctrl_params: params.flow_ctrl.clone(),
            relay_crypt_protocol,
            n_incoming_cells_permitted: params.n_incoming_cells_permitted,
            n_outgoing_cells_permitted: params.n_outgoing_cells_permitted,
        })
    }

    /// Return the negotiated relay crypto protocol.
    pub(crate) fn relay_crypt_protocol(&self) -> RelayCryptLayerProtocol {
        self.relay_crypt_protocol
    }

    /// Return the client circuit-creation extensions that we should use in order to negotiate
    /// these circuit hop parameters.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn circuit_request_extensions(&self) -> Result<Vec<CircRequestExt>> {
        // allow 'unused_mut' because of the combinations of `cfg` conditions below
        #[allow(unused_mut)]
        let mut client_extensions = Vec::new();

        #[allow(unused, unused_mut)]
        let mut cc_extension_set = false;

        if self.ccontrol.is_enabled() {
            cfg_if::cfg_if! {
                if #[cfg(feature = "flowctl-cc")] {
                    client_extensions.push(CircRequestExt::CcRequest(CcRequest::default()));
                    cc_extension_set = true;
                } else {
                    return Err(
                        tor_error::internal!(
                            "Congestion control is enabled on this circuit, but 'flowctl-cc' feature is not enabled"
                        )
                        .into()
                    );
                }
            }
        }

        // See whether we need to send a list of required protocol capabilities.
        // These aren't "negotiated" per se; they're simply demanded.
        // The relay will refuse the circuit if it doesn't support all of them,
        // and if any of them isn't supported in the SubprotocolRequest extension.
        //
        // (In other words, don't add capabilities here just because you want the
        // relay to have them! They must be explicitly listed as supported for use
        // with this extension. For the current list, see
        // https://spec.torproject.org/tor-spec/create-created-cells.html#subproto-request)
        //
        #[allow(unused_mut)]
        let mut required_protocol_capabilities: Vec<tor_protover::NamedSubver> = Vec::new();

        #[cfg(feature = "counter-galois-onion")]
        if matches!(self.relay_crypt_protocol(), RelayCryptLayerProtocol::Cgo) {
            if !cc_extension_set {
                return Err(tor_error::internal!("Tried to negotiate CGO without CC.").into());
            }
            required_protocol_capabilities.push(tor_protover::named::RELAY_CRYPT_CGO);
        }

        if !required_protocol_capabilities.is_empty() {
            client_extensions.push(CircRequestExt::SubprotocolRequest(
                required_protocol_capabilities.into_iter().collect(),
            ));
        }

        Ok(client_extensions)
    }
}

#[cfg(test)]
impl std::default::Default for CircParameters {
    fn default() -> Self {
        Self {
            extend_by_ed25519_id: true,
            ccontrol: crate::congestion::test_utils::params::build_cc_fixed_params(),
            flow_ctrl: FlowCtrlParameters::defaults_for_tests(),
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}

impl CircParameters {
    /// Constructor
    pub fn new(
        extend_by_ed25519_id: bool,
        ccontrol: CongestionControlParams,
        flow_ctrl: FlowCtrlParameters,
    ) -> Self {
        Self {
            extend_by_ed25519_id,
            ccontrol,
            flow_ctrl,
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}

/// Instructions for sending a RELAY cell.
///
/// This instructs a circuit reactor to send a RELAY cell to a given target
/// (a hop, if we are a client, or the client, if we are a relay).
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) struct SendRelayCell {
    /// The hop number, or `None` if we are a relay.
    pub(crate) hop: Option<HopNum>,
    /// Whether to use a RELAY_EARLY cell.
    pub(crate) early: bool,
    /// The cell to send.
    pub(crate) cell: AnyRelayMsgOuter,
}

/// The inbound state of a hop.
pub(crate) struct CircHopInbound {
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    #[allow(dead_code)] // TODO(relay)
    ccontrol: Arc<Mutex<CongestionControl>>,
    /// Decodes relay cells received from this hop.
    decoder: RelayCellDecoder,
    /// Remaining permitted incoming relay cells from this hop, plus 1.
    ///
    /// (In other words, `None` represents no limit,
    /// `Some(1)` represents an exhausted limit,
    /// and `Some(n)` means that n-1 more cells may be received.)
    ///
    /// If this ever decrements from Some(1), then the circuit must be torn down with an error.
    n_incoming_cells_permitted: Option<NonZeroU32>,
}

/// The outbound state of a hop.
pub(crate) struct CircHopOutbound {
    /// Congestion control object.
    ///
    /// This object is also in charge of handling circuit level SENDME logic for this hop.
    ccontrol: Arc<Mutex<CongestionControl>>,
    /// Map from stream IDs to streams.
    ///
    /// We store this with the reactor instead of the circuit, since the
    /// reactor needs it for every incoming cell on a stream, whereas
    /// the circuit only needs it when allocating new streams.
    ///
    /// NOTE: this is behind a mutex because the client reactor polls the `StreamMap`s
    /// of all hops concurrently, in a `FuturesUnordered`. Without the mutex,
    /// this wouldn't be possible, because it would mean holding multiple
    /// mutable references to `self` (the reactor). Note, however,
    /// that there should never be any contention on this mutex:
    /// we never create more than one
    /// `CircHopList::ready_streams_iterator()` stream
    /// at a time, and we never clone/lock the hop's `StreamMap` outside of it.
    ///
    /// Additionally, the stream map of the last hop (join point) of a conflux tunnel
    /// is shared with all the circuits in the tunnel.
    map: Arc<Mutex<StreamMap>>,
    /// Format to use for relay cells.
    //
    // When we have packed/fragmented cells, this may be replaced by a RelayCellEncoder.
    relay_format: RelayCellFormat,
    /// Flow control parameters for new streams.
    flow_ctrl_params: Arc<FlowCtrlParameters>,
    /// Remaining permitted outgoing relay cells from this hop, plus 1.
    ///
    /// If this ever decrements from Some(1), then the circuit must be torn down with an error.
    n_outgoing_cells_permitted: Option<NonZeroU32>,
}

impl CircHopInbound {
    /// Create a new [`CircHopInbound`].
    pub(crate) fn new(
        ccontrol: Arc<Mutex<CongestionControl>>,
        decoder: RelayCellDecoder,
        settings: &HopSettings,
    ) -> Self {
        Self {
            ccontrol,
            decoder,
            n_incoming_cells_permitted: settings.n_incoming_cells_permitted.map(cvt),
        }
    }

    /// Return a mutable reference to our CongestionControl object.
    #[allow(dead_code)] // TODO(relay)
    pub(crate) fn ccontrol(&self) -> MutexGuard<'_, CongestionControl> {
        self.ccontrol.lock().expect("poisoned lock")
    }

    /// Parse a RELAY or RELAY_EARLY cell body.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub(crate) fn decode(&mut self, cell: BoxedCellBody) -> Result<RelayCellDecoderResult> {
        self.decoder
            .decode(cell)
            .map_err(|e| Error::from_bytes_err(e, "relay cell"))
    }

    /// Decrement the limit of inbound cells that may be received from this hop; give
    /// an error if it would reach zero.
    pub(crate) fn decrement_cell_limit(&mut self) -> Result<()> {
        try_decrement_cell_limit(&mut self.n_incoming_cells_permitted)
            .map_err(|_| Error::ExcessInboundCells)
    }
}

impl CircHopOutbound {
    /// Create a new [`CircHopOutbound`].
    pub(crate) fn new(
        ccontrol: Arc<Mutex<CongestionControl>>,
        relay_format: RelayCellFormat,
        flow_ctrl_params: Arc<FlowCtrlParameters>,
        settings: &HopSettings,
    ) -> Self {
        Self {
            ccontrol,
            map: Arc::new(Mutex::new(StreamMap::new())),
            relay_format,
            flow_ctrl_params,
            n_outgoing_cells_permitted: settings.n_outgoing_cells_permitted.map(cvt),
        }
    }

    /// Start a stream. Creates an entry in the stream map with the given channels, and sends the
    /// `message` to the provided hop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_stream(
        &mut self,
        hop: Option<HopNum>,
        message: AnyRelayMsg,
        sender: StreamQueueSender,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
        cmd_checker: AnyCmdChecker,
    ) -> Result<(SendRelayCell, StreamId)> {
        let flow_ctrl = self.build_flow_ctrl(
            Arc::clone(&self.flow_ctrl_params),
            rate_limit_updater,
            drain_rate_requester,
        )?;
        let r =
            self.map
                .lock()
                .expect("lock poisoned")
                .add_ent(sender, rx, flow_ctrl, cmd_checker)?;
        let cell = AnyRelayMsgOuter::new(Some(r), message);
        Ok((
            SendRelayCell {
                hop,
                early: false,
                cell,
            },
            r,
        ))
    }

    /// Close the stream associated with `id` because the stream was dropped.
    ///
    /// If we have not already received an END cell on this stream, send one.
    /// If no END cell is specified, an END cell with the reason byte set to
    /// REASON_MISC will be sent.
    ///
    // Note(relay): `circ_id` is an opaque displayable type
    // because relays use a different circuit ID type
    // than clients. Eventually, we should probably make
    // them both use the same ID type, or have a nicer approach here
    pub(crate) fn close_stream(
        &mut self,
        circ_id: impl std::fmt::Display,
        id: StreamId,
        hop: Option<HopNum>,
        message: CloseStreamBehavior,
        why: streammap::TerminateReason,
        expiry: Instant,
    ) -> Result<Option<SendRelayCell>> {
        let should_send_end = self
            .map
            .lock()
            .expect("lock poisoned")
            .terminate(id, why, expiry)?;
        trace!(
            circ_id = %circ_id,
            stream_id = %id,
            should_send_end = ?should_send_end,
            "Ending stream",
        );
        // TODO: I am about 80% sure that we only send an END cell if
        // we didn't already get an END cell.  But I should double-check!
        if let (ShouldSendEnd::Send, CloseStreamBehavior::SendEnd(end_message)) =
            (should_send_end, message)
        {
            let end_cell = AnyRelayMsgOuter::new(Some(id), end_message.into());
            let cell = SendRelayCell {
                hop,
                early: false,
                cell: end_cell,
            };

            return Ok(Some(cell));
        }
        Ok(None)
    }

    /// Check if we should send an XON message.
    ///
    /// If we should, then returns the XON message that should be sent.
    pub(crate) fn maybe_send_xon(
        &mut self,
        rate: XonKbpsEwma,
        id: StreamId,
    ) -> Result<Option<Xon>> {
        // the call below will return an error if XON/XOFF aren't supported,
        // so we check for support here
        if !self.ccontrol().uses_xon_xoff() {
            return Ok(None);
        }

        let mut map = self.map.lock().expect("lock poisoned");
        let Some(StreamEntMut::Open(ent)) = map.get_mut(id) else {
            // stream went away
            return Ok(None);
        };

        ent.maybe_send_xon(rate)
    }

    /// Check if we should send an XOFF message.
    ///
    /// If we should, then returns the XOFF message that should be sent.
    pub(crate) fn maybe_send_xoff(&mut self, id: StreamId) -> Result<Option<Xoff>> {
        // the call below will return an error if XON/XOFF aren't supported,
        // so we check for support here
        if !self.ccontrol().uses_xon_xoff() {
            return Ok(None);
        }

        let mut map = self.map.lock().expect("lock poisoned");
        let Some(StreamEntMut::Open(ent)) = map.get_mut(id) else {
            // stream went away
            return Ok(None);
        };

        ent.maybe_send_xoff()
    }

    /// Return the format that is used for relay cells sent to this hop.
    ///
    /// For the most part, this format isn't necessary to interact with a CircHop;
    /// it becomes relevant when we are deciding _what_ we can encode for the hop.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.relay_format
    }

    /// Delegate to CongestionControl, for testing purposes
    #[cfg(test)]
    pub(crate) fn send_window_and_expected_tags(&self) -> (u32, Vec<SendmeTag>) {
        self.ccontrol().send_window_and_expected_tags()
    }

    /// Return the number of open streams on this hop.
    ///
    /// WARNING: because this locks the stream map mutex,
    /// it should never be called from a context where that mutex is already locked.
    pub(crate) fn n_open_streams(&self) -> usize {
        self.map.lock().expect("lock poisoned").n_open_streams()
    }

    /// Return a mutable reference to our CongestionControl object.
    pub(crate) fn ccontrol(&self) -> MutexGuard<'_, CongestionControl> {
        self.ccontrol.lock().expect("poisoned lock")
    }

    /// We're about to send `msg`.
    ///
    /// See [`OpenStreamEnt::about_to_send`](crate::streammap::OpenStreamEnt::about_to_send).
    //
    // TODO prop340: This should take a cell or similar, not a message.
    //
    // Note(relay): `circ_id` is an opaque displayable type
    // because relays use a different circuit ID type
    // than clients. Eventually, we should probably make
    // them both use the same ID type, or have a nicer approach here
    pub(crate) fn about_to_send(
        &mut self,
        circ_id: impl std::fmt::Display,
        stream_id: StreamId,
        msg: &AnyRelayMsg,
    ) -> Result<()> {
        let mut hop_map = self.map.lock().expect("lock poisoned");
        let Some(StreamEntMut::Open(ent)) = hop_map.get_mut(stream_id) else {
            warn!(
                circ_id = %circ_id,
                stream_id = %stream_id,
                "sending a relay cell for non-existent or non-open stream!",
            );
            return Err(Error::CircProto(format!(
                "tried to send a relay cell on non-open stream {}",
                sv(stream_id),
            )));
        };

        ent.about_to_send(msg)
    }

    /// Add an entry to this map using the specified StreamId.
    #[cfg(feature = "hs-service")]
    pub(crate) fn add_ent_with_id(
        &self,
        sink: StreamQueueSender,
        rx: StreamMpscReceiver<AnyRelayMsg>,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
        stream_id: StreamId,
        cmd_checker: AnyCmdChecker,
    ) -> Result<()> {
        let mut hop_map = self.map.lock().expect("lock poisoned");
        hop_map.add_ent_with_id(
            sink,
            rx,
            self.build_flow_ctrl(
                Arc::clone(&self.flow_ctrl_params),
                rate_limit_updater,
                drain_rate_requester,
            )?,
            stream_id,
            cmd_checker,
        )?;

        Ok(())
    }

    /// Builds the reactor's flow control handler for a new stream.
    // TODO: remove the `Result` once we remove the "flowctl-cc" feature
    #[cfg_attr(feature = "flowctl-cc", expect(clippy::unnecessary_wraps))]
    fn build_flow_ctrl(
        &self,
        params: Arc<FlowCtrlParameters>,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Result<StreamFlowCtrl> {
        if self.ccontrol().uses_stream_sendme() {
            let window = sendme::StreamSendWindow::new(SEND_WINDOW_INIT);
            Ok(StreamFlowCtrl::new_window(window))
        } else {
            cfg_if::cfg_if! {
                if #[cfg(feature = "flowctl-cc")] {
                    // TODO: Currently arti only supports clients, and we don't support connecting
                    // to onion services while using congestion control, so we hardcode this. In the
                    // future we will need to somehow tell the `CircHop` this so that we can set it
                    // correctly, since we don't want to enable this at exits.
                    let use_sidechannel_mitigations = true;

                    Ok(StreamFlowCtrl::new_xon_xoff(
                        params,
                        use_sidechannel_mitigations,
                        rate_limit_updater,
                        drain_rate_requester,
                    ))
                } else {
                    drop(params);
                    drop(rate_limit_updater);
                    drop(drain_rate_requester);
                    Err(internal!(
                        "`CongestionControl` doesn't use sendmes, but 'flowctl-cc' feature not enabled",
                    ).into())
                }
            }
        }
    }

    /// Deliver `msg` to the specified open stream entry `ent`.
    fn deliver_msg_to_stream(
        streamid: StreamId,
        ent: &mut OpenStreamEnt,
        cell_counts_toward_windows: bool,
        msg: UnparsedRelayMsg,
    ) -> Result<bool> {
        use tor_async_utils::SinkTrySend as _;
        use tor_async_utils::SinkTrySendError as _;

        // The stream for this message exists, and is open.

        // We need to handle SENDME/XON/XOFF messages here, not in the stream's recv() method, or
        // else we'd never notice them if the stream isn't reading.
        //
        // TODO: this logic is the same as `HalfStream::handle_msg`; we should refactor this if
        // possible
        match msg.cmd() {
            RelayCmd::SENDME => {
                ent.put_for_incoming_sendme(msg)?;
                return Ok(false);
            }
            RelayCmd::XON => {
                ent.handle_incoming_xon(msg)?;
                return Ok(false);
            }
            RelayCmd::XOFF => {
                ent.handle_incoming_xoff(msg)?;
                return Ok(false);
            }
            _ => {}
        }

        let message_closes_stream = ent.cmd_checker.check_msg(&msg)? == StreamStatus::Closed;

        if let Err(e) = Pin::new(&mut ent.sink).try_send(msg) {
            if e.is_full() {
                cfg_if::cfg_if! {
                    if #[cfg(not(feature = "flowctl-cc"))] {
                        // If we get here, we either have a logic bug (!), or an attacker
                        // is sending us more cells than we asked for via congestion control.
                        return Err(Error::CircProto(format!(
                            "Stream sink would block; received too many cells on stream ID {}",
                            sv(streamid),
                        )));
                    } else {
                        return Err(internal!(
                            "Stream (ID {}) uses an unbounded queue, but apparently it's full?",
                            sv(streamid),
                        )
                        .into());
                    }
                }
            }
            if e.is_disconnected() && cell_counts_toward_windows {
                // the other side of the stream has gone away; remember
                // that we received a cell that we couldn't queue for it.
                //
                // Later this value will be recorded in a half-stream.
                ent.dropped += 1;
            }
        }

        Ok(message_closes_stream)
    }

    /// Note that we received an END message (or other message indicating the end of
    /// the stream) on the stream with `id`.
    ///
    /// See [`StreamMap::ending_msg_received`](crate::streammap::StreamMap::ending_msg_received).
    #[cfg(feature = "hs-service")]
    pub(crate) fn ending_msg_received(&self, stream_id: StreamId) -> Result<()> {
        let mut hop_map = self.map.lock().expect("lock poisoned");

        hop_map.ending_msg_received(stream_id)?;

        Ok(())
    }

    /// Handle `msg`, delivering it to the stream with the specified `streamid` if appropriate.
    ///
    /// Returns back the provided `msg`, if the message is an incoming stream request
    /// that needs to be handled by the calling code.
    ///
    // TODO: the above is a bit of a code smell -- we should try to avoid passing the msg
    // back and forth like this.
    pub(crate) fn handle_msg<F>(
        &self,
        possible_proto_violation_err: F,
        cell_counts_toward_windows: bool,
        streamid: StreamId,
        msg: UnparsedRelayMsg,
        now: Instant,
    ) -> Result<Option<UnparsedRelayMsg>>
    where
        F: FnOnce(StreamId) -> Error,
    {
        let mut hop_map = self.map.lock().expect("lock poisoned");

        match hop_map.get_mut(streamid) {
            Some(StreamEntMut::Open(ent)) => {
                // Can't have a stream level SENDME when congestion control is enabled.
                let message_closes_stream =
                    Self::deliver_msg_to_stream(streamid, ent, cell_counts_toward_windows, msg)?;

                if message_closes_stream {
                    hop_map.ending_msg_received(streamid)?;
                }
            }
            Some(StreamEntMut::EndSent(EndSentStreamEnt { expiry, .. })) if now >= *expiry => {
                return Err(possible_proto_violation_err(streamid));
            }
            #[cfg(feature = "hs-service")]
            Some(StreamEntMut::EndSent(_))
                if matches!(
                    msg.cmd(),
                    RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
                ) =>
            {
                // If the other side is sending us a BEGIN but hasn't yet acknowledged our END
                // message, just remove the old stream from the map and stop waiting for a
                // response
                hop_map.ending_msg_received(streamid)?;
                return Ok(Some(msg));
            }
            Some(StreamEntMut::EndSent(EndSentStreamEnt { half_stream, .. })) => {
                // We sent an end but maybe the other side hasn't heard.

                match half_stream.handle_msg(msg)? {
                    StreamStatus::Open => {}
                    StreamStatus::Closed => {
                        hop_map.ending_msg_received(streamid)?;
                    }
                }
            }
            #[cfg(feature = "hs-service")]
            None if matches!(
                msg.cmd(),
                RelayCmd::BEGIN | RelayCmd::BEGIN_DIR | RelayCmd::RESOLVE
            ) =>
            {
                return Ok(Some(msg));
            }
            _ => {
                // No stream wants this message, or ever did.
                return Err(possible_proto_violation_err(streamid));
            }
        }

        Ok(None)
    }

    /// Get the stream map of this hop.
    pub(crate) fn stream_map(&self) -> &Arc<Mutex<StreamMap>> {
        &self.map
    }

    /// Set the stream map of this hop to `map`.
    ///
    /// Returns an error if the existing stream map of the hop has any open stream.
    pub(crate) fn set_stream_map(&mut self, map: Arc<Mutex<StreamMap>>) -> StdResult<(), Bug> {
        if self.n_open_streams() != 0 {
            return Err(internal!("Tried to discard existing open streams?!"));
        }

        self.map = map;

        Ok(())
    }

    /// Decrement the limit of outbound cells that may be sent to this hop; give
    /// an error if it would reach zero.
    pub(crate) fn decrement_cell_limit(&mut self) -> Result<()> {
        try_decrement_cell_limit(&mut self.n_outgoing_cells_permitted)
            .map_err(|_| Error::ExcessOutboundCells)
    }
}

/// If `val` is `Some(1)`, return Err(());
/// otherwise decrement it (if it is Some) and return Ok(()).
#[inline]
fn try_decrement_cell_limit(val: &mut Option<NonZeroU32>) -> StdResult<(), ()> {
    // This is a bit verbose, but I've confirmed that it optimizes nicely.
    match val {
        Some(x) => {
            let z = u32::from(*x);
            if z == 1 {
                Err(())
            } else {
                *x = (z - 1).try_into().expect("NonZeroU32 was zero?!");
                Ok(())
            }
        }
        None => Ok(()),
    }
}

/// Convert a limit from the form used in a HopSettings to that used here.
/// (The format we use here is more compact.)
fn cvt(limit: u32) -> NonZeroU32 {
    // See "known limitations" comment on n_incoming_cells_permitted.
    limit
        .saturating_add(1)
        .try_into()
        .expect("Adding one left it as zero?")
}
