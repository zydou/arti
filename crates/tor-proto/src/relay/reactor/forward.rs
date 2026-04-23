//! A relay's view of the forward (away from the client, towards the exit) state of a circuit.

mod extend_handler;

use extend_handler::ExtendRequestHandler;

use crate::channel::{Channel, ChannelSender};
use crate::circuit::CircuitRxReceiver;
use crate::circuit::UniqId;
use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::backward::BackwardReactorCmd;
use crate::circuit::reactor::forward::{ForwardCellDisposition, ForwardHandler};
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::crypto::cell::OutboundRelayLayer;
use crate::crypto::cell::RelayCellBody;
use crate::relay::RelayCircChanMsg;
use crate::util::err::ReactorError;
use crate::{Error, HopNum, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;

use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::CircuitAccount;
use tor_cell::chancell::msg::{AnyChanMsg, Destroy, PaddingNegotiate, Relay};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanMsg, CircId};
use tor_cell::relaycell::msg::{Extended2, SendmeTag};
use tor_cell::relaycell::{RelayCellDecoderResult, RelayCellFormat, RelayCmd, UnparsedRelayMsg};
use tor_error::internal;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::Runtime;

use futures::channel::mpsc;
use futures::{SinkExt as _, future};
use tracing::trace;

use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::Poll;

/// Placeholder for our custom control message type.
type CtrlMsg = ();

/// Placeholder for our custom control command type.
type CtrlCmd = ();

/// The maximum number of RELAY_EARLY cells allowed on a circuit.
///
// TODO(relay): should we come up with a consensus parameter for this? (arti#2349)
const MAX_RELAY_EARLY_CELLS_PER_CIRCUIT: usize = 8;

/// Relay-specific state for the forward reactor.
pub(crate) struct Forward {
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The outbound view of this circuit, if we are not the last hop.
    ///
    /// Delivers cells towards the exit.
    ///
    /// Only set for middle relays.
    outbound: Option<Outbound>,
    /// The cryptographic state for this circuit for inbound cells.
    crypto_out: Box<dyn OutboundRelayLayer + Send>,
    /// The number of RELAY_EARLY cells we have seen so far on this circuit.
    ///
    /// If we see more than [`MAX_RELAY_EARLY_CELLS_PER_CIRCUIT`] RELAY_EARLY cells, we tear down the circuit.
    relay_early_count: usize,
    /// Helper for handling circuit extension requests.
    ///
    /// Used for validating EXTEND2 cells.
    extend_handler: ExtendRequestHandler,
}

/// A type of event issued by the relay forward reactor.
pub(crate) enum CircEvent {
    /// The outcome of an EXTEND2 request.
    ExtendResult(StdResult<ExtendResult, ReactorError>),
}

/// A successful circuit extension result.
pub(crate) struct ExtendResult {
    /// The EXTENDED2 cell to send back to the client.
    extended2: Extended2,
    /// The outbound channel.
    outbound: Outbound,
    /// The reading end of the outbound Tor channel, if we are not the last hop.
    ///
    /// Yields cells moving from the exit towards the client, if we are a middle relay.
    outbound_chan_rx: CircuitRxReceiver,
}

/// The outbound view of a relay circuit.
struct Outbound {
    /// The circuit identifier on the outbound Tor channel.
    circ_id: CircId,
    /// The outbound Tor channel.
    channel: Arc<Channel>,
    /// The sending end of the outbound Tor channel.
    outbound_chan_tx: ChannelSender,
}

/// The outcome of `decode_relay_cell`.
enum CellDecodeResult {
    /// A decrypted cell.
    Recognized(SendmeTag, RelayCellDecoderResult),
    /// A cell we could not decrypt.
    Unrecognizd(RelayCellBody),
}

impl Forward {
    /// Create a new [`Forward`].
    pub(crate) fn new(
        inbound_chan: &Arc<Channel>,
        unique_id: UniqId,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
        event_tx: mpsc::Sender<CircEvent>,
        memquota: CircuitAccount,
    ) -> Self {
        let inbound_peer = Arc::clone(inbound_chan.peer_info());
        let extend_handler =
            ExtendRequestHandler::new(unique_id, chan_provider, inbound_peer, event_tx, memquota);

        Self {
            unique_id,
            // Initially, we are the last hop in the circuit.
            outbound: None,
            crypto_out,
            relay_early_count: 0,
            extend_handler,
        }
    }

    /// Decode `cell`, returning its corresponding hop number, tag and decoded body.
    fn decode_relay_cell<R: Runtime>(
        &mut self,
        hop_mgr: &mut HopMgr<R>,
        cell: Relay,
    ) -> Result<(Option<HopNum>, CellDecodeResult)> {
        // Note: the client reactor will return the actual source hopnum
        let hopnum = None;
        let cmd = cell.cmd();
        let mut body = cell.into_relay_body().into();
        let Some(tag) = self.crypto_out.decrypt_outbound(cmd, &mut body) else {
            return Ok((hopnum, CellDecodeResult::Unrecognizd(body)));
        };

        // The message is addressed to us! Now it's time to handle it...
        let mut hops = hop_mgr.hops().write().expect("poisoned lock");
        let decode_res = hops
            .get_mut(hopnum)
            .ok_or_else(|| internal!("msg from non-existent hop???"))?
            .inbound
            .decode(body.into())?;

        Ok((hopnum, CellDecodeResult::Recognized(tag, decode_res)))
    }

    /// Handle a DROP message.
    #[allow(clippy::unnecessary_wraps)] // Returns Err if circ-padding is enabled
    fn handle_drop(&mut self) -> StdResult<(), ReactorError> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "circ-padding")] {
                Err(internal!("relay circuit padding not yet supported").into())
            } else {
                Ok(())
            }
        }
    }

    /// Handle the outcome of handling an EXTEND2.
    fn handle_extend_result(
        &mut self,
        res: StdResult<ExtendResult, ReactorError>,
    ) -> StdResult<Option<BackwardReactorCmd>, ReactorError> {
        let ExtendResult {
            extended2,
            outbound,
            outbound_chan_rx,
        } = res?;

        self.outbound = Some(outbound);

        Ok(Some(BackwardReactorCmd::HandleCircuitExtended {
            hop: None,
            extended2,
            outbound_chan_rx,
        }))
    }

    /// Handle a RELAY or RELAY_EARLY cell.
    fn handle_relay_cell<R: Runtime>(
        &mut self,
        hop_mgr: &mut HopMgr<R>,
        cell: Relay,
        early: bool,
    ) -> StdResult<Option<ForwardCellDisposition>, ReactorError> {
        if early {
            self.relay_early_count += 1;

            if self.relay_early_count > MAX_RELAY_EARLY_CELLS_PER_CIRCUIT {
                return Err(
                    Error::CircProto("Circuit received too many RELAY_EARLY cells".into()).into(),
                );
            }
        }

        let (hopnum, res) = self.decode_relay_cell(hop_mgr, cell)?;
        let (tag, decode_res) = match res {
            CellDecodeResult::Unrecognizd(body) => {
                self.handle_unrecognized_cell(body, None, early)?;
                return Ok(None);
            }
            CellDecodeResult::Recognized(tag, res) => (tag, res),
        };

        Ok(Some(ForwardCellDisposition::HandleRecognizedRelay {
            cell: decode_res,
            early,
            hopnum,
            tag,
        }))
    }

    /// Handle a forward cell that we could not decrypt.
    fn handle_unrecognized_cell(
        &mut self,
        body: RelayCellBody,
        info: Option<QueuedCellPaddingInfo>,
        early: bool,
    ) -> StdResult<(), ReactorError> {
        // TODO(relay): remove this log once we add some tests
        // and confirm relaying cells works as expected
        // (in practice it will be too noisy to be useful, even at trace level).
        trace!(
            circ_id = %self.unique_id,
            "Forwarding unrecognized cell"
        );

        let Some(chan) = self.outbound.as_mut() else {
            // The client shouldn't try to send us any cells before it gets
            // an EXTENDED2 cell from us
            return Err(Error::CircProto(
                "Asked to forward cell before the circuit was extended?!".into(),
            )
            .into());
        };

        let msg = Relay::from(BoxedCellBody::from(body));
        let relay = if early {
            AnyChanMsg::RelayEarly(msg.into())
        } else {
            AnyChanMsg::Relay(msg)
        };
        let cell = AnyChanCell::new(Some(chan.circ_id), relay);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the input channel, so await won't block.
        chan.outbound_chan_tx.start_send_unpin((cell, info))?;

        Ok(())
    }

    /// Handle a TRUNCATE cell.
    #[allow(clippy::unused_async)] // TODO(relay)
    async fn handle_truncate(&mut self) -> StdResult<(), ReactorError> {
        // TODO(relay): when we implement this, we should try to do better than C Tor:
        // if we have some cells queued for the next hop in the circuit,
        // we should try to flush them *before* tearing it down.
        //
        // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3487#note_3296035
        Err(internal!("TRUNCATE is not implemented").into())
    }

    /// Handle a DESTROY cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_destroy_cell(&mut self, _cell: Destroy) -> StdResult<(), ReactorError> {
        Err(internal!("DESTROY is not implemented").into())
    }

    /// Handle a PADDING_NEGOTIATE cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_padding_negotiate(&mut self, _cell: PaddingNegotiate) -> StdResult<(), ReactorError> {
        Err(internal!("PADDING_NEGOTIATE is not implemented").into())
    }
}

impl ForwardHandler for Forward {
    type BuildSpec = OwnedChanTarget;
    type CircChanMsg = RelayCircChanMsg;
    type CircEvent = CircEvent;

    async fn handle_meta_msg<R: Runtime>(
        &mut self,
        runtime: &R,
        early: bool,
        _hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
        _relay_cell_format: RelayCellFormat,
    ) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::DROP => self.handle_drop(),
            RelayCmd::EXTEND2 => self.extend_handler.handle_extend2(runtime, early, msg),
            RelayCmd::TRUNCATE => self.handle_truncate().await,
            cmd => Err(internal!("relay cmd {cmd} not supported").into()),
        }
    }

    async fn handle_forward_cell<R: Runtime>(
        &mut self,
        hop_mgr: &mut HopMgr<R>,
        cell: RelayCircChanMsg,
    ) -> StdResult<Option<ForwardCellDisposition>, ReactorError> {
        use RelayCircChanMsg::*;

        match cell {
            Relay(r) => self.handle_relay_cell(hop_mgr, r, false),
            RelayEarly(r) => self.handle_relay_cell(hop_mgr, r.into(), true),
            Destroy(d) => {
                self.handle_destroy_cell(d)?;
                Ok(None)
            }
            PaddingNegotiate(p) => {
                self.handle_padding_negotiate(p)?;
                Ok(None)
            }
        }
    }

    fn handle_event(
        &mut self,
        event: Self::CircEvent,
    ) -> StdResult<Option<BackwardReactorCmd>, ReactorError> {
        match event {
            CircEvent::ExtendResult(res) => self.handle_extend_result(res),
        }
    }

    async fn outbound_chan_ready(&mut self) -> Result<()> {
        future::poll_fn(|cx| match &mut self.outbound {
            Some(chan) => {
                let _ = chan.outbound_chan_tx.poll_flush_unpin(cx);

                chan.outbound_chan_tx.poll_ready_unpin(cx)
            }
            None => {
                // Pedantically, if the channel doesn't exist, it can't be ready,
                // but we have no choice here than to return Ready
                // (returning Pending would cause the reactor to lock up).
                //
                // Returning ready here means the base reactor is allowed to read
                // from its inbound channel. This is OK, because if we *do*
                // read a cell from that channel and find ourselves needing to
                // forward it to the next hop, we simply return a proto violation error,
                // shutting down the reactor.
                Poll::Ready(Ok(()))
            }
        })
        .await
    }
}

impl ControlHandler for Forward {
    type CtrlMsg = CtrlMsg;
    type CtrlCmd = CtrlCmd;

    fn handle_cmd(&mut self, cmd: Self::CtrlCmd) -> StdResult<(), ReactorError> {
        let () = cmd;
        Ok(())
    }

    fn handle_msg(&mut self, msg: Self::CtrlMsg) -> StdResult<(), ReactorError> {
        let () = msg;
        Ok(())
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        if let Some(outbound) = self.outbound.as_mut() {
            // This will send a DESTROY down the outbound channel
            let _ = outbound.channel.close_circuit(outbound.circ_id);
        }
    }
}
