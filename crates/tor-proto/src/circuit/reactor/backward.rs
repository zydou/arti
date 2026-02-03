//! A circuit's view of the backward state of the circuit.

use crate::channel::Channel;
use crate::circuit::UniqId;
use crate::circuit::cell_sender::CircuitCellSender;
use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::circhop::CircHopList;
use crate::circuit::reactor::macros::derive_deftly_template_CircuitReactor;
use crate::circuit::reactor::stream::ReadyStreamMsg;
use crate::congestion::{CongestionControl, sendme};
use crate::crypto::cell::RelayCellBody;
use crate::util::err::ReactorError;
use crate::util::msg::ToRelayMsg;
use crate::util::poll_all::PollAll;
use crate::{Error, HopNum, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{
    self, PaddingController, PaddingEvent, PaddingEventStream, QueuedCellPaddingInfo,
};

use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanCmd, CircId};
use tor_cell::relaycell::msg::{Sendme, SendmeTag};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, RelayCmd};
use tor_error::internal;
use tor_rtcompat::{DynTimeProvider, Runtime};

use derive_deftly::Deftly;
use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, future, select_biased};
use tracing::trace;

use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex, RwLock};

use crate::circuit::CircuitRxReceiver;

#[cfg(feature = "circ-padding")]
use crate::circuit::padding::{CircPaddingDisposition, padding_disposition};

/// The "backward" circuit reactor of a relay.
///
/// See the [`reactor`](crate::circuit::reactor) module-level docs.
///
/// Shuts downs down if an error occurs, or if the [`Reactor`](super::Reactor),
/// [`ForwardReactor`](super::ForwardReactor), or if one of the
/// [`StreamReactor`](super::stream::StreamReactor)s of this circuit shuts down:
///
///   * if the `Reactor` shuts down, we are alerted via the ctrl/command mpsc channels
///     (their sending ends will close, which causes run_once() to return ReactorError::Shutdown)
///   * if `ForwardReactor` shuts down, the `Reactor` will notice and will itself shut down,
///     which, in turn, causes the `BackwardReactor` to shut down as described above
///   * if one of the `StreamReactor`s shuts down, the `ForwardReactor` will
///     notice when it next tries to deliver a stream message to it, and shut down,
///     causing the `BackwardReactor` and top-level `Reactor` to follow suit
#[derive(Deftly)]
#[derive_deftly(CircuitReactor)]
#[deftly(reactor_name = "backward reactor")]
#[deftly(run_inner_fn = "Self::run_once")]
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(super) struct BackwardReactor<B: BackwardHandler> {
    /// The time provider.
    time_provider: DynTimeProvider,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The circuit identifier on the backward Tor channel.
    circ_id: CircId,
    /// Implementation-dependent part of the reactor.
    ///
    /// This enables us to customize the behavior of the reactor,
    /// depending on whether we are a client or a relay.
    inner: B,
    /// The reading end of the outbound Tor channel, if we are not the last hop.
    ///
    /// Yields cells moving from the exit towards the client, if we are a middle relay.
    outbound_chan_rx: Option<CircuitRxReceiver>,
    /// The per-hop state, shared with the forward reactor.
    ///
    /// The backward reactor acquires a read lock to this whenever it needs to
    ///
    ///   * send a circuit-level SENDME
    ///   * handle a circuit-level SENDME
    ///   * send a padding cell
    ///
    // Note: For the sending/handling of SENDMEs, we lock the hop list
    // to extract the relay cell format and CC state of the hop.
    // Technically, for the SENDME cases, we could've avoided locking
    // the hop list from the BWD, by having the FWD share the relay cell format
    // and CC state in the BackwardReactorCmd::{Send,Handle}Sendme command.
    // But for the padding case, we *need* the hop list, because we need
    // to work out what relay cell format to use when sending the padding cell.
    // But for the sake of simplicity, I made the BWD consult the CircHopList in all cases.
    //
    // TODO: the backward reactor only ever reads from this.
    // Conceptually, it is the foward reactor's HopMgr that owns this list:
    // only HopMgr can add hops to the list.
    //
    // Perhaps we need a specialized abstraction that only allows reading here.
    // This could be a wrapper over RwLock, providing a read-only API.
    hops: Arc<RwLock<CircHopList>>,
    /// The sending end of the backward Tor channel.
    ///
    /// Delivers cells towards the other endpoint: towards the client, if we are a relay,
    /// or towards the exit, if we are a client.
    inbound_chan_tx: CircuitCellSender,
    /// Channel for receiving control commands.
    command_rx: mpsc::UnboundedReceiver<CtrlCmd<B::CtrlCmd>>,
    /// Channel for receiving control messages.
    control_rx: mpsc::UnboundedReceiver<CtrlMsg<B::CtrlMsg>>,
    /// Receiver for [`BackwardReactorCmd`]s coming from the forward reactor.
    ///
    /// The sender is in [`ForwardReactor`](super::ForwardReactor), which will forward all cells
    /// carrying Tor stream data to us.
    ///
    /// This serves a dual purpose:
    ///
    ///   * it enables the `ForwardReactor` to deliver Tor stream data received
    ///     from the other endpoint
    ///   * it lets the `BackwardReactor` know if the `ForwardReactor` has shut down:
    ///     we select! on this MPSC channel in the main loop, so if the `ForwardReactor`
    ///     shuts down, we will get EOS upon calling `.next()`)
    forward_reactor_rx: mpsc::Receiver<BackwardReactorCmd>,
    /// A channel for receiving endpoint-bound stream messages from the StreamReactor(s)
    /// (the stream messages are client-bound if we are a relay, or exit-bound if we are a client).
    stream_rx: mpsc::Receiver<ReadyStreamMsg>,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
    /// An event stream telling us about padding-related events.
    padding_event_stream: PaddingEventStream,
    /// Current rules for blocking traffic, according to the padding controller.
    #[cfg(feature = "circ-padding")]
    padding_block: Option<padding::StartBlocking>,
}

/// A control message aimed at the generic forward reactor.
pub(crate) enum CtrlMsg<M> {
    /// An implementation-dependent control message.
    #[allow(unused)] // TODO(relay)
    Custom(M),
}

/// A control command aimed at the generic forward reactor.
pub(crate) enum CtrlCmd<C> {
    /// An implementation-dependent control command.
    #[allow(unused)] // TODO(relay)
    Custom(C),
}

/// Trait for customizing the behavior of the backward reactor.
///
/// Used for plugging in the implementation-dependent (client vs relay)
/// parts of the implementation into the generic one.
pub(crate) trait BackwardHandler: ControlHandler {
    /// The subclass of ChanMsg that can arrive on this type of circuit.
    type CircChanMsg: TryFrom<AnyChanMsg, Error = crate::Error> + ToRelayMsg + Send;

    /// Encrypt a RelayCellBody that is moving in the backward direction.
    fn encrypt_relay_cell(
        &mut self,
        cmd: ChanCmd,
        body: &mut RelayCellBody,
        hop: Option<HopNum>,
    ) -> SendmeTag;
}

#[allow(unused)] // TODO(relay)
impl<B: BackwardHandler> BackwardReactor<B> {
    /// Create a new [`BackwardReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new<R: Runtime>(
        runtime: R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        inner: B,
        hops: Arc<RwLock<CircHopList>>,
        forward_reactor_rx: mpsc::Receiver<BackwardReactorCmd>,
        control_rx: mpsc::UnboundedReceiver<CtrlMsg<B::CtrlMsg>>,
        command_rx: mpsc::UnboundedReceiver<CtrlCmd<B::CtrlCmd>>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        stream_rx: mpsc::Receiver<ReadyStreamMsg>,
    ) -> Self {
        let inbound_chan_tx = CircuitCellSender::from_channel_sender(channel.sender());

        Self {
            time_provider: DynTimeProvider::new(runtime),
            outbound_chan_rx: None,
            inner,
            hops,
            inbound_chan_tx,
            unique_id,
            circ_id,
            forward_reactor_rx,
            control_rx,
            command_rx,
            stream_rx,
            padding_ctrl,
            padding_event_stream,
            #[cfg(feature = "circ-padding")]
            padding_block: None,
        }
    }

    /// Helper for [`run`](Self::run).
    ///
    /// Handles cells arriving on the outbound Tor channel,
    /// and writes cells to the inbound Tor channel.
    ///
    /// Because the Tor application streams, the `forward_reactor_rx` MPSC streams,
    /// and the outbound Tor channel MPSC stream are driven concurrently using [`PollAll`],
    /// this function can send up to 3 cells per call over the inbound Tor channel:
    ///
    ///    * a cell carrying Tor stream data
    ///    * a cell received from the outbound Tor channel, if we are a relay
    ///      (moving from the exit towards the client)
    ///    * a circuit-level SENDME
    ///
    /// However, in practice, leaky pipe is not really used,
    /// and so relays that have application streams (i.e. the exits),
    /// are not going to have an outbound Tor channel,
    /// and so this will only really drive Tor stream data,
    /// delivering at most 2 cells per call.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        use postage::prelude::{Sink as _, Stream as _};

        /// The maximum number of events we expect to handle per reactor loop.
        ///
        /// This is bounded by the number of futures we push into the PollAll.
        const PER_LOOP_EVENT_COUNT: usize = 3;

        // A collection of futures we plan to drive concurrently.
        let mut poll_all =
            PollAll::<PER_LOOP_EVENT_COUNT, Option<CircuitEvent<B::CircChanMsg>>>::new();

        // Flush the backward Tor channel sink, and check it for readiness
        //
        // TODO(flushing): here and everywhere else we need to flush:
        //
        // Currently, we try to flush every time we want to write to the sink,
        // but may be suboptimal.
        //
        // However, we don't actually *wait* for the flush to complete
        // (we just make a bit of progress by calling poll_flush),
        // so it's possible that this is actually tolerable.
        // We should run some tests, and if this turns out to be a performance bottleneck,
        // we'll have to rethink our flushing approach.
        let backward_chan_ready = future::poll_fn(|cx| {
            // The flush outcome doesn't matter,
            // so we simply move on to the readiness check.
            // The reason we don't wait on the flush is because we don't
            // want to flush on *every* reactor loop, but we do want to make
            // a bit of progress each time.
            //
            // (TODO: do we want to handle errors here?)
            let _ = self.inbound_chan_tx.poll_flush_unpin(cx);

            self.inbound_chan_tx.poll_ready_unpin(cx)
        });

        // Concurrently, drive :
        //  1. a future that reads from the StreamReactor, to see if there are
        //  any application streams that have a message to send
        //  (this resolves to a message that needs to be delivered to the peer)
        poll_all.push(async {
            // Internally, each stream reactor checks if we're allowed to send anything
            // that counts towards SENDME windows (and ceases to send us stream data if not)
            //
            // The reason we don't check that here is because stream_rx multiplexes stream data
            // from all hops, and we have no way of knowing which hop will want to send us stream
            // data next, and therefore we can't know which hop's CC object to use
            self.stream_rx.next().await.map(CircuitEvent::Send)
        });

        //  2. the stream of commands coming from the ForwardReactor
        //  (this resolves to a BackwardReactorCmd)
        poll_all.push(async {
            let event = match self.forward_reactor_rx.next().await {
                Some(cmd) => CircuitEvent::Forwarded(cmd),
                None => {
                    // The forward reactor has crashed, so we have to shut down.
                    CircuitEvent::ForwardShutdown
                }
            };

            Some(event)
        });

        // 3. Messages moving from the outbound channel towards the inbound Tor channel,
        // if we have an outbound Tor channel.
        //
        // NOTE: in practice, clients and exits won't have an outbound Tor channel,
        // so for them this will be a no-op.
        poll_all.push(async {
            let event = if let Some(outbound_chan_rx) = self.outbound_chan_rx.as_mut() {
                // Forward channel unexpectedly closed, we should close too
                match outbound_chan_rx.next().await {
                    Some(msg) => match msg.try_into() {
                        Err(e) => CircuitEvent::ProtoViolation(e),
                        Ok(cell) => CircuitEvent::Cell(cell),
                    },
                    None => {
                        // The forward reactor has crashed, so we have to shut down.
                        CircuitEvent::ForwardShutdown
                    }
                }
            } else {
                future::pending().await
            };

            Some(event)
        });

        let poll_all = async move {
            // Avoid polling **any** of the futures if the outgoing sink is blocked.
            //
            // This implements backpressure: we avoid reading from our input sources
            // if we know we're unable to write to the inbound Tor channel sink.
            //
            // More specifically, if our inbound Tor channel sink is full and can no longer
            // accept cells, we stop reading:
            //
            //   1. From the application streams (received from StreamReactor), if there are any.
            //
            //   2. From the forward_reactor_rx channel, used by the forward reactor to send us
            //
            //     - a circuit-level SENDME that we have received, or
            //     - a circuit-level SENDME that we need to deliver to the client
            //
            //     Not reading from the forward_reactor_rx channel, in turn, causes the forward reactor
            //     to block and therefore stop reading from **its** input sources,
            //     propagating backpressure all the way to the other endpoint of the circuit.
            //
            //   3. From the outbound Tor channel, if there is one.
            //
            // This will delay any SENDMEs the client or exit might have sent along
            // the way, and therefore count as a congestion signal.
            //
            // TODO: memquota setup to make sure this doesn't turn into a memory DOS vector
            let _ = backward_chan_ready.await;

            // TODO: it's important to not block reading from the forward_reactor_rx channel on the chan
            // sender readiness (for instance, we should not block the sending of SENDMEs
            // if the channel is blocked on a padding-induced block).
            //
            // This means we will need to move the forward_reactor_rx handling out of the PollAll
            // to the select_biased! below.
            poll_all.await
        };

        let events = select_biased! {
            res = self.command_rx.next().fuse() => {
                let cmd = res.ok_or_else(|| ReactorError::Shutdown)?;
                self.handle_cmd(cmd)?;
                return Ok(());
            }
            res = self.control_rx.next().fuse() => {
                let msg = res.ok_or_else(|| ReactorError::Shutdown)?;
                self.handle_msg(msg)?;
                return Ok(());
            }
            res = self.padding_event_stream.next().fuse() => {
                // If there's a padding event, we need to handle it immediately,
                // because it might tell us to start blocking the inbound_chan_tx sink,
                // which, in turn, means we need to stop trying to read from
                // the application streams.
                let event = res.ok_or_else(|| ReactorError::Shutdown)?;

                cfg_if::cfg_if! {
                    if #[cfg(feature = "circ-padding")] {
                        self.run_padding_event(event).await?;
                    } else {
                        // If padding isn't enabled, we never generate a padding event,
                        // so we can be sure this case will never be called.
                        void::unreachable(event.0);
                    }
                }
                return Ok(())
            }
            res = poll_all.fuse() => res,
        };

        // Note: there shouldn't be more than N < PER_LOOP_EVENT_COUNT events to handle
        // per reactor loop. We need to be careful here, because we must avoid blocking
        // the reactor.
        //
        // If handling more than one event per loop turns out to be a problem, we may
        // need to dispatch this to a background task instead.
        for event in events.into_iter().flatten() {
            self.handle_event(event).await?;
        }

        Ok(())
    }

    /// Handle a control command.
    fn handle_cmd(&mut self, cmd: CtrlCmd<B::CtrlCmd>) -> StdResult<(), ReactorError> {
        match cmd {
            CtrlCmd::Custom(c) => self.inner.handle_cmd(c),
        }
    }

    /// Handle a control message.
    fn handle_msg(&mut self, msg: CtrlMsg<B::CtrlMsg>) -> StdResult<(), ReactorError> {
        match msg {
            CtrlMsg::Custom(c) => self.inner.handle_msg(c),
        }
    }

    /// Perform some circuit-padding-based event on the specified circuit.
    //
    // TODO(DEDUP): this is almost identical to the client-side Conflux::run_padding_event()
    #[cfg(feature = "circ-padding")]
    async fn run_padding_event(
        &mut self,
        padding_event: PaddingEvent,
    ) -> StdResult<(), ReactorError> {
        use PaddingEvent as E;

        match padding_event {
            E::SendPadding(send_padding) => {
                self.send_padding(send_padding).await?;
            }
            E::StartBlocking(start_blocking) => {
                self.start_blocking_for_padding(start_blocking);
            }
            E::StopBlocking => {
                self.stop_blocking_for_padding();
            }
        }
        Ok(())
    }

    /// Handle a request from our padding subsystem to send a padding packet.
    //
    // TODO(DEDUP): this is almost identical to the client-side Client::send_padding()
    #[cfg(feature = "circ-padding")]
    async fn send_padding(&mut self, send_padding: padding::SendPadding) -> Result<()> {
        use CircPaddingDisposition::*;

        let target_hop = send_padding.hop;

        match padding_disposition(
            &send_padding,
            &self.inbound_chan_tx,
            self.padding_block.as_ref(),
        ) {
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

    /// Enable padding-based blocking,
    /// or change the rule for padding-based blocking to the one in `block`.
    //
    // TODO(DEDUP): copy of Client::start_blocking_for_padding()
    #[cfg(feature = "circ-padding")]
    pub(super) fn start_blocking_for_padding(&mut self, block: padding::StartBlocking) {
        self.inbound_chan_tx.start_blocking();
        self.padding_block = Some(block);
    }

    /// Disable padding-based blocking.
    ///
    // TODO(DEDUP): copy of Client::stop_blocking_for_padding()
    #[cfg(feature = "circ-padding")]
    pub(super) fn stop_blocking_for_padding(&mut self) {
        self.inbound_chan_tx.stop_blocking();
        self.padding_block = None;
    }

    /// Generate and encrypt a padding cell, and send it to a targeted hop.
    ///
    /// Ignores any padding-based blocking.
    ///
    // TODO(DEDUP): copy of Client::queue_padding_cell_for_hop()
    #[cfg(feature = "circ-padding")]
    async fn queue_padding_cell_for_hop(
        &mut self,
        target_hop: HopNum,
        queue_info: Option<QueuedCellPaddingInfo>,
    ) -> Result<()> {
        use tor_cell::relaycell::msg::Drop as DropMsg;

        let msg = AnyRelayMsgOuter::new(None, DropMsg::default().into());
        let hopnum = Some(target_hop);

        // TODO: the ccontrol state isn't actually needed here, because
        // DROP cells don't count towards SENDME windows.
        // Technically, we could avoid unnecessarily Arc::clone()ing the CC state
        // here, and just extract the relay cell format.
        // But for that we would need a specialized send_relay_cell_inner()-like function
        // that doesn't take a CC object, or to make the CC object optional in
        // send_relay_cell_inner().
        let (relay_cell_format, ccontrol) = self.hop_info(hopnum)?;

        self.send_relay_cell_inner(hopnum, relay_cell_format, msg, false, &ccontrol, queue_info)
            .await
    }

    /// Determine how exactly to handle a request to handle padding.
    #[cfg(feature = "circ-padding")]
    fn padding_disposition(&self, send_padding: &padding::SendPadding) -> CircPaddingDisposition {
        crate::circuit::padding::padding_disposition(
            send_padding,
            &self.inbound_chan_tx,
            self.padding_block.as_ref(),
        )
    }

    /// Handle a circuit event.
    async fn handle_event(
        &mut self,
        event: CircuitEvent<B::CircChanMsg>,
    ) -> StdResult<(), ReactorError> {
        use CircuitEvent::*;

        match event {
            Cell(cell) => self.handle_backward_cell(cell),
            Send(msg) => {
                let ReadyStreamMsg {
                    hop,
                    relay_cell_format,
                    msg,
                    ccontrol,
                } = msg;

                self.send_relay_cell(hop, relay_cell_format, msg, false, &ccontrol)
                    .await?;

                Ok(())
            }
            Forwarded(cmd) => self.handle_reactor_cmd(cmd).await,
            ForwardShutdown => {
                // The forward reactor has crashed, so we have to shut down.
                trace!(
                    circ_id = %self.unique_id,
                    "Backward relay reactor shutdown (forward reactor has closed)",
                );

                Err(ReactorError::Shutdown)
            }
            ProtoViolation(err) => Err(err.into()),
        }
    }

    /// Return the RelayCellFormat and CC state of a given hop.
    fn hop_info(
        &self,
        hopnum: Option<HopNum>,
    ) -> Result<(RelayCellFormat, Arc<Mutex<CongestionControl>>)> {
        let hops = self.hops.read().expect("poisoned lock");
        let hop = hops
            .get(hopnum)
            .ok_or_else(|| internal!("tried to send padding to non-existent hop?!"))?;
        let relay_cell_format = hop.settings.relay_crypt_protocol().relay_cell_format();
        let ccontrol = Arc::clone(&hop.ccontrol);

        Ok((relay_cell_format, ccontrol))
    }

    /// Handle a command sent to us by the forward reactor.
    async fn handle_reactor_cmd(&mut self, msg: BackwardReactorCmd) -> StdResult<(), ReactorError> {
        use BackwardReactorCmd::*;

        match msg {
            SendRelayMsg { hop, msg } => {
                self.send_relay_msg(hop, msg).await?;
            }
            HandleSendme { hop, sendme } => {
                self.handle_sendme(hop, sendme).await?;
                return Ok(());
            }
        }

        Ok(())
    }

    /// Send a relay message to the specified hop.
    async fn send_relay_msg(
        &mut self,
        hopnum: Option<HopNum>,
        msg: AnyRelayMsgOuter,
    ) -> StdResult<(), ReactorError> {
        let (relay_cell_format, ccontrol) = self.hop_info(hopnum)?;
        let cmd = msg.cmd();

        self.send_relay_cell(hopnum, relay_cell_format, msg, false, &ccontrol)
            .await?;

        if cmd == RelayCmd::SENDME {
            ccontrol.lock().expect("poisoned lock").note_sendme_sent();
        }

        Ok(())
    }

    /// Handle a circuit-level SENDME (stream ID = 0).
    ///
    /// Returns an error if the SENDME does not have an authentication tag
    /// (versions of Tor <=0.3.5 omit the SENDME tag, but we don't support
    /// those any longer).
    ///
    /// Any error returned from this function will shut down the reactor.
    ///
    // TODO(DEDUP): duplicates the logic from the client-side Circuit::handle_sendme()
    async fn handle_sendme(
        &mut self,
        hopnum: Option<HopNum>,
        sendme: Sendme,
    ) -> StdResult<(), ReactorError> {
        let tag = sendme
            .into_sendme_tag()
            .ok_or_else(|| Error::CircProto("missing tag on circuit sendme".into()))?;

        // NOTE: it's okay to await. We are only awaiting on the congestion_signals
        // future which *should* resolve immediately
        let signals = self.inbound_chan_tx.congestion_signals().await;

        let hops = self.hops.read().expect("poisoned lock");
        let hop = hops
            .get(hopnum)
            .ok_or_else(|| internal!("tried to send padding to non-existent hop?!"))?;

        // Update the CC object that we received a SENDME along
        // with possible congestion signals.
        hop.ccontrol
            .lock()
            .expect("poisoned lock")
            .note_sendme_received(&self.time_provider, tag, signals)?;

        Ok(())
    }

    /// Encode `msg` and encrypt it, returning the resulting cell
    /// and tag that should be expected for an authenticated SENDME sent
    /// in response to that cell.
    ///
    // TODO(DEDUP): duplicates the logic from the client-side Circuit::encode_relay_cell()
    fn encode_relay_cell(
        &mut self,
        relay_format: RelayCellFormat,
        hop: Option<HopNum>,
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

        // Use the implementation-dependent encryption logic
        let tag = self.inner.encrypt_relay_cell(cmd, &mut body, hop);
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
    async fn send_relay_cell(
        &mut self,
        hop: Option<HopNum>,
        relay_cell_format: RelayCellFormat,
        msg: AnyRelayMsgOuter,
        early: bool,
        ccontrol: &Arc<Mutex<CongestionControl>>,
    ) -> Result<()> {
        self.send_relay_cell_inner(hop, relay_cell_format, msg, early, ccontrol, None)
            .await
    }

    /// As [`send_relay_cell`](Self::send_relay_cell), but takes an optional
    /// [`QueuedCellPaddingInfo`] in `padding_info`.
    ///
    /// If `padding_info` is None, `msg` must be non-padding: we report it as such to the
    /// padding controller.
    ///
    // TODO(DEDUP): this contains parts of Circuit::send_relay_cell_inner()
    async fn send_relay_cell_inner(
        &mut self,
        hop: Option<HopNum>,
        relay_cell_format: RelayCellFormat,
        msg: AnyRelayMsgOuter,
        early: bool,
        ccontrol: &Arc<Mutex<CongestionControl>>,
        padding_info: Option<QueuedCellPaddingInfo>,
    ) -> Result<()> {
        let c_t_w = sendme::cmd_counts_towards_windows(msg.cmd());
        let (msg, tag) = self.encode_relay_cell(relay_cell_format, hop, early, msg)?;
        let cell = AnyChanCell::new(Some(self.circ_id), msg);

        // TODO: we use HopNum(0) if we're a relay (i.e. if the hop is None).
        // Is that ok?
        let hop = hop.unwrap_or_else(|| HopNum::from(0));
        // Remember that we've enqueued this cell.
        let padding_info = padding_info.or_else(|| self.padding_ctrl.queued_data(hop));

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the async streams, so await won't block.
        Pin::new(&mut self.inbound_chan_tx)
            .send_unbounded((cell, padding_info))
            .await?;

        if c_t_w {
            ccontrol
                .lock()
                .expect("poisoned lock")
                .note_data_sent(&self.time_provider, &tag)?;
        }

        Ok(())
    }

    /// Handle a backward cell (moving from the exit towards the client).
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_backward_cell(&mut self, _cell: B::CircChanMsg) -> StdResult<(), ReactorError> {
        Err(internal!("Cell relaying is not implemented").into())
    }
}

/// A circuit event that must be handled by the [`BackwardReactor`].
enum CircuitEvent<M> {
    /// We received a cell that needs to be handled.
    ///
    /// The cell is client-bound if we are a relay, or exit-bound if we are a client).
    Cell(M),
    /// We received a RELAY cell from the stream reactor that needs
    /// to be packaged and written to our Tor channel.
    ///
    /// The message is client-bound if we are a relay, or exit-bound if we are a client).
    Send(ReadyStreamMsg),
    /// We received a cell from the ForwardReactor that we need to handle.
    ///
    /// This might be
    ///
    ///   * a circuit-level SENDME that we have received, or
    ///   * a circuit-level SENDME that we need to deliver to the client
    Forwarded(BackwardReactorCmd),
    /// The forward reactor has shut down.
    ///
    /// We need to shut down too.
    ForwardShutdown,
    /// Protocol violation.
    ///
    /// This can happen if we receive a channel message that is not supported on the channel.
    ProtoViolation(Error),
}

/// Instructions from the forward reactor.
pub(crate) enum BackwardReactorCmd {
    /// A circuit SENDME we received from the other endpoint.
    HandleSendme {
        /// The hop the SENDME came on.
        hop: Option<HopNum>,
        /// The SENDME.
        sendme: Sendme,
    },
    /// A SENDME we need to send back to the other endpoint.
    SendRelayMsg {
        /// The hop to encode the message for.
        hop: Option<HopNum>,
        /// The message to send.
        msg: AnyRelayMsgOuter,
    },
}
