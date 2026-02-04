//! A circuit's view of the forward state of the circuit.

use crate::circuit::UniqId;
use crate::circuit::reactor::backward::BackwardReactorCmd;
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::circuit::reactor::macros::derive_deftly_template_CircuitReactor;
use crate::circuit::reactor::stream::StreamMsg;
use crate::circuit::reactor::{ControlHandler, ReactorResultChannel};
use crate::congestion::sendme;
use crate::crypto::cell::RelayCellBody;
use crate::stream::cmdcheck::AnyCmdChecker;
use crate::stream::msg_streamid;
use crate::util::err::ReactorError;
use crate::util::msg::ToRelayMsg;
use crate::{Error, HopNum, Result};

#[cfg(any(feature = "hs-service", feature = "relay"))]
use crate::stream::incoming::{
    IncomingStreamRequestFilter, IncomingStreamRequestHandler, StreamReqSender,
};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, QueuedCellPaddingInfo};

use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::msg::Relay;
use tor_cell::relaycell::msg::{Sendme, SendmeTag};
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellDecoderResult, RelayCellFormat, RelayCmd, UnparsedRelayMsg,
};
use tor_error::internal;
use tor_linkspec::HasRelayIds;
use tor_rtcompat::Runtime;

use derive_deftly::Deftly;
use either::Either;
use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, select_biased};
use tracing::debug;

use std::result::Result as StdResult;

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
    /// Hop manager, storing per-hop state, and handles to the stream reactors.
    ///
    /// Contains the `CircHopList`.
    hop_mgr: HopMgr<R>,
    /// An implementation-specific event stream.
    ///
    /// Polled from the main loop of the reactor.
    /// Each event is passed to [`ForwardHandler::handle_event`].
    circ_events: mpsc::Receiver<F::CircEvent>,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
}

/// A control command aimed at the generic forward reactor.
pub(crate) enum CtrlCmd<C> {
    /// Begin accepting streams on this circuit.
    //
    // TODO(DEDUP): this is very similar to its client-side counterpart,
    // except the hop is a Option<HopNum> instead of a TargetHop.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
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
    type CircChanMsg: TryFrom<AnyChanMsg, Error = crate::Error> + ToRelayMsg;

    /// An opaque event type.
    ///
    /// The [`ForwardReactor`] polls an MPSC stream yielding `CircEvent`s from the main loop.
    /// Each event is passed to [`Self::handle_event`] for handling.
    type CircEvent;

    /// Decode `cell`, returning its corresponding hop number, tag and decoded body.
    fn decode_relay_cell<R: Runtime>(
        &mut self,
        hop_mgr: &mut HopMgr<R>,
        cell: Relay,
    ) -> Result<(Option<HopNum>, CellDecodeResult)>;

    /// Handle a non-SENDME RELAY message on this circuit with stream ID 0.
    async fn handle_meta_msg<R: Runtime>(
        &mut self,
        runtime: &R,
        hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
        relay_cell_format: RelayCellFormat,
    ) -> StdResult<(), ReactorError>;

    /// Handle a forward cell that we could not decrypt.
    ///
    /// Only used by relays.
    fn handle_unrecognized_cell(
        &mut self,
        body: RelayCellBody,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError>;

    /// Handle a forward (TODO terminology) cell.
    ///
    /// The cell is
    ///   - moving from the client towards the exit, if we're a relay
    ///   - moving from the guard towards us, if we're a client
    async fn handle_forward_cell(&mut self, cell: Self::CircChanMsg)
    -> StdResult<(), ReactorError>;

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

impl<R: Runtime, F: ForwardHandler> ForwardReactor<R, F> {
    /// Create a new [`ForwardReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        runtime: R,
        unique_id: UniqId,
        inner: F,
        hop_mgr: HopMgr<R>,
        inbound_chan_rx: CircuitRxReceiver,
        control_rx: mpsc::UnboundedReceiver<CtrlMsg<F::CtrlMsg>>,
        command_rx: mpsc::UnboundedReceiver<CtrlCmd<F::CtrlCmd>>,
        backward_reactor_tx: mpsc::Sender<BackwardReactorCmd>,
        circ_events: mpsc::Receiver<F::CircEvent>,
        padding_ctrl: PaddingController,
    ) -> Self {
        Self {
            runtime,
            unique_id,
            inbound_chan_rx,
            control_rx,
            command_rx,
            inner,
            backward_reactor_tx,
            hop_mgr,
            circ_events,
            padding_ctrl,
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
                self.handle_cmd(cmd)
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
                        circ_id = %self.unique_id,
                        "Backward channel has closed, shutting down forward relay reactor",
                    );

                    return Err(ReactorError::Shutdown);
                };

                let cell: F::CircChanMsg = cell.try_into()?;
                match cell.to_relay_msg() {
                    Either::Left(r) => self.handle_relay_cell(r).await,
                    Either::Right(cell) => {
                        self.inner.handle_forward_cell(cell).await
                    }
                }
            },
        }
    }

    /// Handle a control command.
    fn handle_cmd(&mut self, cmd: CtrlCmd<F::CtrlCmd>) -> StdResult<(), ReactorError> {
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

                // Update the HopMgr with the
                let ret = self.hop_mgr.set_incoming_handler(handler);
                let _ = done.send(ret); // don't care if the corresponding receiver goes away.
                Ok(())
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

    /// Note that we have received a RELAY cell.
    ///
    /// Updates the padding and CC state.
    fn note_relay_cell_received(
        &self,
        hopnum: Option<HopNum>,
        c_t_w: bool,
    ) -> Result<(RelayCellFormat, bool)> {
        let mut hops = self.hop_mgr.hops().write().expect("poisoned lock");
        let hop = hops
            .get_mut(hopnum)
            .ok_or_else(|| internal!("msg from non-existant hop???"))?;

        // Check whether we are allowed to receive more data for this circuit hop.
        hop.inbound.decrement_cell_limit()?;

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            hop.ccontrol
                .lock()
                .expect("poisoned lock")
                .note_data_received()?
        } else {
            false
        };

        let relay_cell_format = hop.settings.relay_crypt_protocol().relay_cell_format();

        Ok((relay_cell_format, send_circ_sendme))
    }

    /// Handle a RELAY cell.
    ///
    // TODO(DEDUP): very similar to Client::handle_relay_cell()
    async fn handle_relay_cell(&mut self, cell: Relay) -> StdResult<(), ReactorError> {
        let (hopnum, res) = self.inner.decode_relay_cell(&mut self.hop_mgr, cell)?;
        let (tag, decode_res) = match res {
            CellDecodeResult::Unrecognizd(body) => {
                return self.inner.handle_unrecognized_cell(body, None);
            }
            CellDecodeResult::Recognized(tag, res) => (tag, res),
        };

        // For padding purposes, if we are a relay, we set the hopnum to 0
        // TODO(relay): is this right?
        let hopnum_padding = hopnum.unwrap_or_else(|| HopNum::from(0));
        if decode_res.is_padding() {
            self.padding_ctrl.decrypted_padding(hopnum_padding)?;
        } else {
            self.padding_ctrl.decrypted_data(hopnum_padding);
        }

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);
        let (relay_cell_format, send_circ_sendme) = self.note_relay_cell_received(hopnum, c_t_w)?;

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
            // the congestion control object right here (via hop_mgr).
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
            match self
                .handle_relay_msg(hopnum, msg, relay_cell_format, c_t_w)
                .await
            {
                Ok(()) => continue,
                Err(e) => {
                    for m in msgs {
                        debug!(
                            circ_id = %self.unique_id,
                            "Ignoring relay msg received after triggering shutdown: {m:?}",
                        );
                    }
                    if let Some(incomplete) = incomplete {
                        debug!(
                            circ_id = %self.unique_id,
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
        hop: Option<HopNum>,
        msg: UnparsedRelayMsg,
        relay_cell_format: RelayCellFormat,
        cell_counts_toward_windows: bool,
    ) -> StdResult<(), ReactorError> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(sid) = streamid else {
            return self.handle_meta_msg(hop, msg, relay_cell_format).await;
        };

        let msg = StreamMsg {
            sid,
            msg,
            cell_counts_toward_windows,
        };

        // All messages on streams are handled in the stream reactor
        // (because that's where the stream map is)
        //
        // Internally, this will spawn a StreamReactor for the target hop,
        // if not already spawned.
        self.hop_mgr.send(hop, msg).await
    }

    /// Handle a RELAY message on this circuit with stream ID 0.
    async fn handle_meta_msg(
        &mut self,
        hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
        relay_cell_format: RelayCellFormat,
    ) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::SENDME => {
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
            _ => {
                self.inner
                    .handle_meta_msg(&self.runtime, hopnum, msg, relay_cell_format)
                    .await
            }
        }
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

/// The outcome of `decode_relay_cell`.
pub(crate) enum CellDecodeResult {
    /// A decrypted cell.
    Recognized(SendmeTag, RelayCellDecoderResult),
    /// A cell we could not decrypt.
    Unrecognizd(RelayCellBody),
}
