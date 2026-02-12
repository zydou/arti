//! A relay's view of the forward (away from the client, towards the exit) state of a circuit.

use crate::channel::{Channel, ChannelSender};
use crate::circuit::CircuitRxReceiver;
use crate::circuit::UniqId;
use crate::circuit::create::{Create2Wrap, CreateHandshakeWrap};
use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::backward::BackwardReactorCmd;
use crate::circuit::reactor::forward::{CellDecodeResult, ForwardHandler};
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::crypto::cell::OutboundRelayLayer;
use crate::crypto::cell::RelayCellBody;
use crate::relay::RelayCircChanMsg;
use crate::util::err::ReactorError;
use crate::{Error, HopNum, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;

use crate::relay::channel_provider::{ChannelProvider, ChannelResult, OutboundChanSender};
use tor_cell::chancell::msg::{AnyChanMsg, Destroy, PaddingNegotiate, Relay, RelayEarly};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanMsg, CircId};
use tor_cell::relaycell::msg::{Extend2, Extended2};
use tor_cell::relaycell::{RelayCellFormat, RelayCmd, UnparsedRelayMsg};
use tor_error::{internal, into_internal, warn_report};
use tor_linkspec::decode::Strictness;
use tor_linkspec::{OwnedChanTarget, OwnedChanTargetBuilder};
use tor_rtcompat::{Runtime, SpawnExt as _};

use futures::channel::mpsc;
use futures::{SinkExt as _, StreamExt as _, future};

use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::Poll;

/// Placeholder for our custom control message type.
type CtrlMsg = ();

/// Placeholder for our custom control command type.
type CtrlCmd = ();

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
    /// A handle to a [`ChannelProvider`], used for initiating outgoing Tor channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying Tor channel provider (`ChanMgr`),
    /// to enable the reuse of existing Tor channels where possible.
    chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send>,
    /// Whether we have received an EXTEND2 on this circuit.
    ///
    // TODO(relay): bools can be finicky.
    // Maybe we should combine this bool and the optional
    // outbound into a new state machine type
    // (with states Initial -> Extending -> Extended(Outbound))?
    // But should not do this if it turns out more convoluted than the bool-based approach.
    have_seen_extend2: bool,
    /// A stream of events to be read from the main loop of the reactor.
    event_tx: mpsc::Sender<CircEvent>,
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

impl Forward {
    /// Create a new [`Forward`].
    pub(crate) fn new(
        unique_id: UniqId,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send>,
        event_tx: mpsc::Sender<CircEvent>,
    ) -> Self {
        Self {
            unique_id,
            // Initially, we are the last hop in the circuit.
            outbound: None,
            crypto_out,
            chan_provider,
            have_seen_extend2: false,
            event_tx,
        }
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

    /// Handle an EXTEND2 cell.
    ///
    /// This spawns a background task for dealing with the circuit extension,
    /// which then reports back the result via the [`Self::event_tx`] MPSC stream.
    /// Note that this MPSC stream is polled from the `ForwardReactor` main loop,
    /// and each `CircEvent` is passed back to [`Self::handle_event()`[ for handling.
    fn handle_extend2<R: Runtime>(
        &mut self,
        runtime: &R,
        msg: UnparsedRelayMsg,
    ) -> StdResult<(), ReactorError> {
        // Check if we're in the right state before parsing the EXTEND2
        if self.have_seen_extend2 {
            return Err(Error::CircProto("got 2 EXTEND2 on the same circuit?!".into()).into());
        }

        self.have_seen_extend2 = true;

        let to_bytes_err = |e| Error::from_bytes_err(e, "EXTEND2 message");

        let extend2 = msg.decode::<Extend2>().map_err(to_bytes_err)?.into_msg();

        let chan_target = OwnedChanTargetBuilder::from_encoded_linkspecs(
            Strictness::Standard,
            extend2.linkspecs(),
        )
        .map_err(|err| Error::LinkspecDecodeErr {
            object: "EXTEND2",
            err,
        })?
        .build()
        .map_err(|_| {
            // TODO: should we include the error in the circ proto error context?
            Error::CircProto("Invalid channel target".into())
        })?;

        // Note: we don't do any further validation on the EXTEND2 here,
        // under the assumption it will be handled by the ChannelProvider.

        let (chan_tx, chan_rx) = mpsc::unbounded();

        let chan_tx = OutboundChanSender(chan_tx);
        Arc::clone(&self.chan_provider).get_or_launch(self.unique_id, chan_target, chan_tx)?;

        let mut result_tx = self.event_tx.clone();
        let rt = runtime.clone();

        // TODO(relay): because we dispatch this the entire EXTEND2 handling to a background task,
        // we don't really need the channel provider to send us the outcome via an MPSC channel,
        // because get_or_launch() could simply be async (it wouldn't block the reactor,
        // because it runs in another task). Maybe we need to rethink the ChannelProvider API?
        runtime
            .spawn(async move {
                let res = Self::extend_circuit(rt, extend2, chan_rx).await;

                // Discard the error if the reactor shut down before we had
                // a chance to complete the extend handshake
                let _ = result_tx.send(CircEvent::ExtendResult(res)).await;
            })
            .map_err(into_internal!("failed to spawn extend task?!"))?;

        Ok(())
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

    /// Extend this circuit on the channel received on `chan_rx`.
    ///
    /// Note: this gets spawned in a background task from
    /// [`Self::handle_extend2`] so as not to block the reactor main loop.
    ///
    #[allow(unused_variables)] // will become used once we implement CREATED2 timeouts
    async fn extend_circuit<R: Runtime>(
        _runtime: R,
        extend2: Extend2,
        mut chan_rx: mpsc::UnboundedReceiver<ChannelResult>,
    ) -> StdResult<ExtendResult, ReactorError> {
        // We expect the channel build timeout to be enforced by the ChannelProvider
        let chan_res = chan_rx
            .next()
            .await
            .ok_or_else(|| internal!("channel provider task exited"))?;

        let channel = match chan_res {
            Ok(c) => c,
            Err(e) => {
                warn_report!(e, "Failed to launch outgoing channel");
                // Note: retries are handled within
                // get_or_launch(), so if we receive an
                // error at this point, we need to bail
                return Err(ReactorError::Shutdown);
            }
        };

        // Now that we finally have a forward Tor channel,
        // it's time to forward the onion skin and extend the circuit...
        //
        // Note: the only reason we need to await here is because internally
        // new_outbound_circ() sends a control message to the channel reactor handles,
        // which is handled asynchronously. In practice, we're not actually waiting on
        // the network here, so in theory we shouldn't need a timeout for this operation.
        let (circ_id, outbound_chan_rx, createdreceiver) = channel.new_outbound_circ().await?;

        // We have allocated a circuit in the channel's circmap,
        // now it's time to send the CREATE2 and wait for the response.
        let create2_wrap = Create2Wrap {
            handshake_type: extend2.handshake_type(),
        };
        let create2 = create2_wrap.to_chanmsg(extend2.handshake().into());

        // Time to write the CREATE2 to the outbound channel...
        let mut outbound_chan_tx = channel.sender();
        let cell = AnyChanCell::new(Some(circ_id), create2);
        outbound_chan_tx.send((cell, None)).await?;

        // TODO(relay): we need a timeout here, otherwise we might end up waiting forever
        // for the CREATED2 to arrive.
        //
        // There is some complexity here, see
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3648#note_3340125
        let response = createdreceiver
            .await
            .map_err(|_| internal!("channel disappeared?"))?;

        let outbound = Outbound {
            circ_id,
            channel: Arc::clone(&channel),
            outbound_chan_tx,
        };

        // If we reach this point, it means we have extended
        // the circuit by one hop, so we need to take the contents
        // of the CREATE/CREATED2 cell, and package an EXTEND/EXTENDED2
        // to send back to the client.
        let created2_body = create2_wrap.decode_chanmsg(response)?;
        let extended2 = Extended2::new(created2_body);

        Ok(ExtendResult {
            extended2,
            outbound,
            outbound_chan_rx,
        })
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

    /// Handle a RELAY_EARLY cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_relay_early_cell(&mut self, _cell: RelayEarly) -> StdResult<(), ReactorError> {
        Err(internal!("RELAY_EARLY is not implemented").into())
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
            .ok_or_else(|| internal!("msg from non-existant hop???"))?
            .inbound
            .decode(body.into())?;

        Ok((hopnum, CellDecodeResult::Recognized(tag, decode_res)))
    }

    async fn handle_meta_msg<R: Runtime>(
        &mut self,
        runtime: &R,
        _hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
        _relay_cell_format: RelayCellFormat,
    ) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::DROP => self.handle_drop(),
            RelayCmd::EXTEND2 => self.handle_extend2(runtime, msg),
            RelayCmd::TRUNCATE => self.handle_truncate().await,
            cmd => Err(internal!("relay cmd {cmd} not supported").into()),
        }
    }

    fn handle_unrecognized_cell(
        &mut self,
        body: RelayCellBody,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError> {
        let Some(chan) = self.outbound.as_mut() else {
            // The client shouldn't try to send us any cells before it gets
            // an EXTENDED2 cell from us
            return Err(Error::CircProto(
                "Asked to forward cell before the circuit was extended?!".into(),
            )
            .into());
        };

        let msg = Relay::from(BoxedCellBody::from(body));
        let relay = AnyChanMsg::Relay(msg);
        let cell = AnyChanCell::new(Some(chan.circ_id), relay);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the input channel, so await won't block.
        chan.outbound_chan_tx.start_send_unpin((cell, info))?;

        Ok(())
    }

    async fn handle_forward_cell(&mut self, cell: RelayCircChanMsg) -> StdResult<(), ReactorError> {
        use RelayCircChanMsg::*;

        match cell {
            Relay(_) => {
                Err(internal!("relay cell should've been handled in base reactor?!").into())
            }
            RelayEarly(r) => self.handle_relay_early_cell(r),
            Destroy(d) => self.handle_destroy_cell(d),
            PaddingNegotiate(p) => self.handle_padding_negotiate(p),
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
