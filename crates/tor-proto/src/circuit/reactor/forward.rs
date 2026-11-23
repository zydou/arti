//! A circuit's view of the forward state of the circuit.

use crate::circuit::UniqId;
use crate::circuit::metrics::CircuitMetrics;
use crate::circuit::reactor::backward::BackwardReactorCmd;
use crate::circuit::reactor::circ_state::CircuitState;
use crate::circuit::reactor::macros::derive_deftly_template_CircuitReactor;
use crate::circuit::reactor::stream;
use crate::circuit::reactor::{ControlHandler, ReactorResultChannel};
use crate::congestion::sendme;
use crate::stream::cmdcheck::AnyCmdChecker;
use crate::stream::msg_streamid;
use crate::util::err::ReactorError;
use crate::{Error, HopNum, Result};

#[cfg(any(feature = "hs-service", feature = "relay"))]
use {
    crate::stream::CloseStreamBehavior,
    crate::stream::incoming::{
        IncomingStreamRequestFilter, IncomingStreamRequestHandler, StreamReqSender,
    },
};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::PaddingController;

use tor_cell::chancell::{CircId, msg::AnyChanMsg};
use tor_cell::relaycell::flow_ctrl::XonKBpsEwma;
use tor_cell::relaycell::msg::{Sendme, SendmeTag};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoderResult, RelayCmd, StreamId, UnparsedRelayMsg,
};
use tor_linkspec::HasRelayIds;
use tor_rtcompat::Runtime;

use derive_deftly::Deftly;
use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, select_biased};
use std::result::Result as StdResult;
use std::sync::Arc;
use tracing::debug;

use crate::circuit::CircuitRxReceiver;

/// The forward circuit reactor.
///
/// See the [`reactor`](crate::circuit::reactor) module-level docs.
///
/// Shuts downs down if an error occurs, or if either the [`Reactor`](super::Reactor)
/// or the [`BackwardReactor`](super::BackwardReactor) shuts down:
///
///   * if the `Reactor` shuts down, we are alerted via the ctrl/command mpsc channels
///     (their sending ends will close, which causes run_once() to return ReactorError::Shutdown)
///   * if `BackwardReactor` shuts down, the `Reactor` will notice and will itself shut down,
///     which, in turn, causes the `ForwardReactor` to shut down as described above
#[derive(Deftly)]
#[derive_deftly(CircuitReactor)]
#[deftly(reactor_name = "forward reactor")]
#[deftly(run_inner_fn = "Self::run_once")]
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(super) struct ForwardReactor<R: Runtime, F: ForwardHandler> {
    /// A handle to the runtime.
    runtime: R,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The circuit identifier on the inbound Tor channel.
    circ_id: CircId,
    /// Implementation-dependent part of the reactor.
    ///
    /// This enables us to customize the behavior of the reactor,
    /// depending on whether we are a client or a relay.
    inner: F,
    /// Channel for receiving control commands.
    command_rx: mpsc::UnboundedReceiver<CtrlCmd<F::CtrlCmd>>,
    /// Channel for receiving control messages.
    control_rx: mpsc::UnboundedReceiver<CtrlMsg<F::CtrlMsg>>,
    /// The reading end of the inbound Tor channel.
    ///
    /// Yields cells moving from the client towards the exit, if we are a relay,
    /// or cells moving towards *us*, if we are a client.
    inbound_chan_rx: CircuitRxReceiver,
    /// Sender for sending commands to the BackwardReactor.
    ///
    /// Used for sending:
    ///
    ///    * circuit-level SENDMEs received from the other endpoint
    ///      (`[BackwardReactorCmd::HandleSendme]`)
    ///    * circuit-level SENDMEs that need to be delivered to the other endpoint
    ///      (using `[BackwardReactorCmd::SendRelayMsg]`)
    ///
    /// The receiver is in [`BackwardReactor`](super::BackwardReactor), which is responsible for
    /// sending cell over the inbound channel.
    backward_reactor_tx: mpsc::Sender<BackwardReactorCmd>,
    /// The per-hop state of the circuit.
    ///
    /// Contains the `CircHopList` and handles to the corresponding stream reactors.
    circ_state: CircuitState<R>,
    /// An implementation-specific event stream.
    ///
    /// Polled from the main loop of the reactor.
    /// Each event is passed to [`ForwardHandler::handle_event`].
    circ_events: mpsc::Receiver<F::CircEvent>,
    /// Sender for for the circ_events MPSC.
    ///
    /// This is unused, but we need it here in order to keep the circ_events MPSC open,
    /// even if this circuit has already used (and dropped) its ExtendRequestHandler
    /// (the ExtendRequestHandler holds a sending end to this MPSC channel).
    //
    //
    // TODO(relay): this whole circ_events indirection is hard to follow and brittle.
    // It would be nice if we could replace it with a simpler approach
    #[allow(unused)]
    circ_events_tx: mpsc::Sender<F::CircEvent>,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
    /// The circuit metrics.
    metrics: Arc<CircuitMetrics>,
}

/// A control command aimed at the generic forward reactor.
pub(crate) enum CtrlCmd<C> {
    /// Begin accepting streams on this circuit.
    //
    // TODO(DEDUP): this is very similar to its client-side counterpart,
    // except the hop is a Option<HopNum> instead of a TargetHop.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    #[allow(unused)] // TODO(dedup): this will be used by hs services
    AwaitStreamRequests {
        /// A channel for sending information about an incoming stream request.
        incoming_sender: StreamReqSender,
        /// A `CmdChecker` to keep track of which message types are acceptable.
        cmd_checker: AnyCmdChecker,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
        /// The hop that is allowed to create streams.
        ///
        /// Set to None if we are a relay wanting to accept stream requests.
        hop: Option<HopNum>,
        /// A filter used to check requests before passing them on.
        filter: Box<dyn IncomingStreamRequestFilter>,
    },

    /// Close the specified pending incoming stream, sending the provided END message.
    ///
    /// A stream is said to be pending if the message for initiating the stream was received but
    /// not has not been responded to yet.
    ///
    /// This should be used by responders for closing pending incoming streams initiated by the
    /// other party on the circuit.
    ///
    /// TODO(dedup): this is almost identical to the ClosePendingStream control message
    /// from the client-side. We can get rid of the duplication by rewriting
    /// the client circuit reactor to use the new multi-reactor architecture
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    ClosePendingStream {
        /// The hop number the stream is on.
        ///
        /// Set to None if we are a relay.
        hop: Option<HopNum>,
        /// The stream ID to send the END for.
        stream_id: StreamId,
        /// The END message to send, if any.
        message: CloseStreamBehavior,
        /// Oneshot channel to notify on completion.
        done: ReactorResultChannel<()>,
    },
    /// Inform the stream reactor that the drain rate of a stream has changed so that it
    /// can send an XON if needed.
    ///
    /// This is routed to the stream reactor because the it owns the stream map and the
    /// XON/XOFF state. It is also the reactor that decides to send an XOFF or not. It is
    /// in charge of sending the XON to the backward reactor if need be.
    StreamDrainRateUpdate {
        /// The hop number the stream is on.
        ///
        /// Set to None if we are a relay.
        hop: Option<HopNum>,
        /// The stream ID to send the XON on.
        stream_id: StreamId,
        /// The drain rate to advertise in the XON.
        rate: XonKBpsEwma,
    },
    /// An implementation-dependent control command.
    #[allow(unused)] // TODO(relay)
    Custom(C),
}

/// A control message aimed at the generic forward reactor.
pub(crate) enum CtrlMsg<M> {
    /// An implementation-dependent control message.
    #[allow(unused)] // TODO(relay)
    Custom(M),
}

/// Trait for customizing the behavior of the forward reactor.
///
/// Used for plugging in the implementation-dependent (client vs relay)
/// parts of the implementation into the generic one.
pub(crate) trait ForwardHandler: ControlHandler {
    /// Type that explains how to build an outgoing channel.
    type BuildSpec: HasRelayIds;

    /// The subclass of ChanMsg that can arrive on this type of circuit.
    type CircChanMsg: TryFrom<AnyChanMsg, Error = crate::Error>;

    /// An opaque event type.
    ///
    /// The [`ForwardReactor`] polls an MPSC stream yielding `CircEvent`s from the main loop.
    /// Each event is passed to [`Self::handle_event`] for handling.
    type CircEvent;

    /// Handle a non-SENDME RELAY message on this circuit with stream ID 0.
    async fn handle_meta_msg<R: Runtime>(
        &mut self,
        runtime: &R,
        early: bool,
        hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
    ) -> StdResult<(), ReactorError>;

    /// Handle a forward (TODO terminology) cell.
    ///
    /// The cell is
    ///   - moving from the client towards the exit, if we're a relay
    ///   - moving from the guard towards us, if we're a client
    ///
    /// Returns an error if the cell should cause the reactor to shut down,
    /// or a [`ForwardCellDisposition`] specifying how it should be handled.
    ///
    /// Returns `None` if the cell was handled internally by this handler.
    async fn handle_forward_cell<R: Runtime>(
        &mut self,
        circ_state: &CircuitState<R>,
        cell: Self::CircChanMsg,
    ) -> StdResult<Option<ForwardCellDisposition>, ReactorError>;

    /// Handle an implementation-specific circuit event.
    ///
    /// Returns a command for the backward reactor.
    fn handle_event(
        &mut self,
        event: Self::CircEvent,
    ) -> StdResult<Option<BackwardReactorCmd>, ReactorError>;

    /// Wait until the outbound channel, if there is one, is ready to accept more cells.
    ///
    /// Resolves immediately if there is no outbound channel.
    /// Blocks if there is a pending outbound channel.
    async fn outbound_chan_ready(&mut self) -> Result<()>;
}

/// What action to take in response to a cell arriving on our inbound Tor channel.
pub(crate) enum ForwardCellDisposition {
    /// Handle a decoded RELAY or RELAY_EARLY cell in the [`ForwardReactor`].
    HandleRecognizedRelay {
        /// The decoded cell.
        cell: RelayCellDecoderResult,
        /// Whether this was a RELAY_EARLY.
        early: bool,
        /// The hop this cell was for.
        hopnum: Option<HopNum>,
        /// The SENDME tag.
        tag: SendmeTag,
    },
}

impl<R: Runtime, F: ForwardHandler> ForwardReactor<R, F> {
    /// Create a new [`ForwardReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        runtime: R,
        unique_id: UniqId,
        circ_id: CircId,
        inner: F,
        circ_state: CircuitState<R>,
        inbound_chan_rx: CircuitRxReceiver,
        control_rx: mpsc::UnboundedReceiver<CtrlMsg<F::CtrlMsg>>,
        command_rx: mpsc::UnboundedReceiver<CtrlCmd<F::CtrlCmd>>,
        backward_reactor_tx: mpsc::Sender<BackwardReactorCmd>,
        circ_events: mpsc::Receiver<F::CircEvent>,
        circ_events_tx: mpsc::Sender<F::CircEvent>,
        padding_ctrl: PaddingController,
        metrics: Arc<CircuitMetrics>,
    ) -> Self {
        Self {
            runtime,
            unique_id,
            circ_id,
            inbound_chan_rx,
            control_rx,
            command_rx,
            inner,
            backward_reactor_tx,
            circ_state,
            circ_events,
            circ_events_tx,
            padding_ctrl,
            metrics,
        }
    }

    /// Helper for [`run`](Self::run).
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        let outbound_chan_ready = self.inner.outbound_chan_ready();

        let inbound_chan_rx_fut = async {
            // Avoid reading from the inbound_chan_rx Tor Channel if the outgoing sink is blocked
            outbound_chan_ready.await?;
            Ok(self.inbound_chan_rx.next().await)
        };

        select_biased! {
            res = self.command_rx.next().fuse() => {
                let cmd = res.ok_or_else(|| ReactorError::Shutdown)?;
                self.handle_cmd(cmd).await
            }
            res = self.control_rx.next().fuse() => {
                let msg = res.ok_or_else(|| ReactorError::Shutdown)?;
                self.handle_msg(msg)
            }
            res = self.circ_events.next().fuse() => {
                let ev = res.ok_or_else(|| ReactorError::Shutdown)?;
                if let Some(cmd) = self.inner.handle_event(ev)? {
                    self.send_reactor_cmd(cmd).await?;
                }

                Ok(())
            }
            res = inbound_chan_rx_fut.fuse() => {
                let cell = res.map_err(ReactorError::Err)?;
                let Some(cell) = cell else {
                    debug!(
                        circ_uniq_id = %self.unique_id,
                        backward_circ_id = %self.circ_id,
                        "Backward channel has closed, shutting down forward relay reactor",
                    );

                    return Err(ReactorError::Shutdown);
                };
                // TODO(relay): This assumes cells travel in the forward direction.
                self.metrics.forward_cell_read();

                let cell: F::CircChanMsg = cell.try_into()?;
                let Some(disp) = self.inner.handle_forward_cell(&self.circ_state, cell).await? else {
                    return Ok(());
                };

                match disp {
                    ForwardCellDisposition::HandleRecognizedRelay { cell, early, hopnum, tag } => {
                        self.handle_relay_cell(cell, early, hopnum, tag).await
                    }
                }
            },
        }
    }

    /// Handle a control command.
    #[allow(clippy::unused_async)] // used if any(feature = "hs-service", feature = "relay")
    async fn handle_cmd(&mut self, cmd: CtrlCmd<F::CtrlCmd>) -> StdResult<(), ReactorError> {
        match cmd {
            #[cfg(any(feature = "hs-service", feature = "relay"))]
            CtrlCmd::AwaitStreamRequests {
                incoming_sender,
                cmd_checker,
                done,
                hop,
                filter,
            } => {
                let handler = IncomingStreamRequestHandler {
                    incoming_sender,
                    cmd_checker,
                    hop_num: hop,
                    filter,
                };

                let ret = self.circ_state.set_incoming_handler(handler);
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.
                Ok(())
            }
            #[cfg(any(feature = "hs-service", feature = "relay"))]
            CtrlCmd::ClosePendingStream {
                hop,
                stream_id,
                message,
                done,
            } => {
                let ret = self.circ_state.close_pending(hop, stream_id, message).await;
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.

                Ok(())
            }
            CtrlCmd::StreamDrainRateUpdate {
                hop,
                stream_id,
                rate,
            } => {
                let msg = stream::CtrlMsg::DrainRateUpdate { stream_id, rate };
                self.circ_state.send(hop, msg).await
            }
            CtrlCmd::Custom(c) => self.inner.handle_cmd(c),
        }
    }

    /// Handle a control message.
    fn handle_msg(&mut self, msg: CtrlMsg<F::CtrlMsg>) -> StdResult<(), ReactorError> {
        match msg {
            CtrlMsg::Custom(c) => self.inner.handle_msg(c),
        }
    }

    /// Handle a RELAY cell.
    ///
    // TODO(DEDUP): very similar to Client::handle_relay_cell()
    async fn handle_relay_cell(
        &mut self,
        decode_res: RelayCellDecoderResult,
        early: bool,
        hopnum: Option<HopNum>,
        tag: SendmeTag,
    ) -> StdResult<(), ReactorError> {
        // For padding purposes, if we are a relay, we set the hopnum to 0
        // TODO(relay): is this right?
        let hopnum_padding = hopnum.unwrap_or_else(|| HopNum::from(0));
        if decode_res.is_padding() {
            self.padding_ctrl.decrypted_padding(hopnum_padding)?;
        } else {
            self.padding_ctrl.decrypted_data(hopnum_padding);
        }

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);
        let send_circ_sendme = self
            .circ_state
            .shared()
            .note_relay_cell_received(hopnum, c_t_w)?;

        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let sendme = Sendme::from(tag);
            let msg = AnyRelayMsgOuter::new(None, sendme.into());
            let forward = BackwardReactorCmd::SendRelayMsg { hop: hopnum, msg };

            // NOTE: sending the SENDME to the backward reactor for handling
            // might seem counterintuitive, given that we have access to
            // the congestion control object right here (via circ_state).
            //
            // However, the forward reactor does not have access to the
            // outbound_chan_tx part of the inbound (towards the client) Tor channel,
            // and so it cannot handle the SENDME on its own
            // (because it cannot obtain the congestion signals),
            // so the SENDME needs to be handled in the backward reactor.
            //
            // NOTE: this will block if the backward reactor is not ready
            // to send any more cells.
            self.send_reactor_cmd(forward).await?;
        }

        let (mut msgs, incomplete) = decode_res.into_parts();
        while let Some(msg) = msgs.next() {
            match self.handle_relay_msg(early, hopnum, msg, c_t_w).await {
                Ok(()) => continue,
                Err(e) => {
                    for m in msgs {
                        debug!(
                            circ_uniq_id = %self.unique_id,
                            backward_circ_id = %self.circ_id,
                            "Ignoring relay msg received after triggering shutdown: {m:?}",
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!(
                            circ_uniq_id = %self.unique_id,
                            backward_circ_id = %self.circ_id,
                            "Ignoring partial relay msg received after triggering shutdown: {:?}",
                            incomplete,
                        );
                    }

                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single incoming RELAY message.
    async fn handle_relay_msg(
        &mut self,
        early: bool,
        hop: Option<HopNum>,
        msg: UnparsedRelayMsg,
        cell_counts_toward_windows: bool,
    ) -> StdResult<(), ReactorError> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        if let Some(sid) = streamid {
            self.handle_stream_msg(early, hop, msg, sid, cell_counts_toward_windows)
                .await
        } else {
            self.handle_meta_msg(early, hop, msg).await
        }
    }

    /// Handle a stream message arriving on this circuit.
    async fn handle_stream_msg(
        &mut self,
        _early: bool,
        hop: Option<HopNum>,
        msg: UnparsedRelayMsg,
        sid: StreamId,
        cell_counts_toward_windows: bool,
    ) -> StdResult<(), ReactorError> {
        // TODO(relay): return an error if this arrived in an RELAY_EARLY?

        let msg = stream::CtrlMsg::DeliverStreamMsg {
            sid,
            msg,
            cell_counts_toward_windows,
        };

        // All messages on streams are handled in the stream reactor
        // (because that's where the stream map is)
        //
        // Internally, this will spawn a StreamReactor for the target hop,
        // if not already spawned.
        self.circ_state.send(hop, msg).await
    }

    /// Handle a RELAY or RELAY_EARLY message on this circuit with stream ID 0.
    async fn handle_meta_msg(
        &mut self,
        early: bool,
        hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
    ) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::SENDME => self.handle_sendme(hopnum, msg).await,
            _ => {
                self.inner
                    .handle_meta_msg(&self.runtime, early, hopnum, msg)
                    .await
            }
        }
    }

    /// Handle a circuit SENDME coming from the specified `hopnum`.
    async fn handle_sendme(
        &mut self,
        hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
    ) -> StdResult<(), ReactorError> {
        let sendme = msg
            .decode::<Sendme>()
            .map_err(|e| Error::from_bytes_err(e, "sendme message"))?
            .into_msg();

        let cmd = BackwardReactorCmd::HandleSendme {
            hop: hopnum,
            sendme,
        };

        self.send_reactor_cmd(cmd).await
    }

    /// Send a command to the backward reactor.
    ///
    /// Blocks if the `backward_reactor_tx` channel is full, i.e. if the backward reactor
    /// is not ready to send any more cells.
    ///
    /// Returns an error if the backward reactor has shut down.
    async fn send_reactor_cmd(
        &mut self,
        forward: BackwardReactorCmd,
    ) -> StdResult<(), ReactorError> {
        self.backward_reactor_tx.send(forward).await.map_err(|_| {
            // The other reactor has shut down
            ReactorError::Shutdown
        })
    }
}
