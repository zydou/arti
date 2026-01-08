//! A relay's view of the forward (away from the client, towards the exit) state of the circuit.

use crate::channel::ChannelSender;
use crate::circuit::UniqId;
use crate::circuit::circhop::CircHopInbound;
use crate::congestion::sendme;
use crate::crypto::cell::{OutboundRelayLayer, RelayCellBody};
use crate::relay::RelayCircChanMsg;
use crate::relay::channel_provider::{ChannelProvider, ChannelResult};
use crate::stream::msg_streamid;
use crate::util::err::ReactorError;
use crate::{Error, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, QueuedCellPaddingInfo};

use super::backward::BackwardReactorCmd;

use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::msg::{Destroy, PaddingNegotiate, Relay, RelayEarly};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanMsg, CircId};
use tor_cell::relaycell::msg::Sendme;
use tor_cell::relaycell::{RelayCmd, UnparsedRelayMsg};
use tor_error::{internal, trace_report, warn_report};
use tor_linkspec::HasRelayIds;

use futures::SinkExt;
use futures::channel::mpsc;
use futures::{FutureExt as _, StreamExt, future, select_biased};
use postage::broadcast;
use tracing::{debug, trace};

use std::result::Result as StdResult;
use std::task::Poll;

use super::CircuitRxReceiver;

/// The forward circuit reactor.
///
/// Handles the "forward direction": moves cells towards the exit.
///
/// Shuts downs down if an error occurs, or if either the [`Reactor`](super::Reactor)
/// or the [`BackwardReactor`](super::BackwardReactor) shuts down:
///
///   * if `Reactor` shuts down, we are alerted via the `shutdown_tx` broadcast channel
///     (we will notice this its closure in the main loop)
///   * if `BackwardReactor` shuts down, `Reactor` will notice, and itself shutdown
///     (as in the previous case, we will notice this because the `shutdown_tx` channel will close)
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(super) struct ForwardReactor<T: HasRelayIds> {
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The inbound hop state
    hop: CircHopInbound,
    /// An MPSC channel for receiving newly opened outgoing [`Channel`](crate::channel::Channel)s.
    ///
    /// This channel is polled from the main loop of the reactor,
    /// and is used when extending the circuit.
    outgoing_chan_rx: mpsc::UnboundedReceiver<ChannelResult>,
    /// The cryptographic state for this circuit for inbound cells.
    crypto_out: Box<dyn OutboundRelayLayer + Send>,
    /// The reading end of the backward Tor channel.
    ///
    /// Yields cells moving from the client towards the exit.
    input: CircuitRxReceiver,
    /// The sending end of the forward channel, if we are not the last hop.
    ///
    /// Delivers cells towards the exit.
    forward: Option<Forward>,
    /// Sender for RELAY cells that need to be forwarded to the client,
    /// or otherwise handled in the BackwardReactor.
    ///
    /// Used for sending:
    ///
    ///    * circuit-level SENDMEs received from the client (`[BackwardReactorCmd::HandleSendme]`)
    ///    * circuit-level SENDMEs that need to be delivered to the client
    ///      (`[BackwardReactorCmd::SendSendme]`)
    ///    * stream messages, i.e. messages with a non-zero stream ID (`[BackwardReactorCmd::HandleMsg]`)
    ///
    /// The receiver is in [`BackwardReactor`](super::BackwardReactor), which is responsible for
    /// sending all client-bound cells.
    cell_tx: mpsc::Sender<BackwardReactorCmd>,
    /// A handle to a [`ChannelProvider`], used for initiating outgoing Tor channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying Tor channel provider (`ChanMgr`),
    /// to enable the reuse of existing Tor channels where possible.
    chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
    /// A padding controller to which padding-related events should be reported.
    padding_ctrl: PaddingController,
    /// A broadcast receiver used to detect when the
    /// [`Reactor`](super::Reactor) or
    /// [`BackwardReactor`](super::BackwardReactor) are dropped.
    shutdown_rx: broadcast::Receiver<void::Void>,
}

/// A relay's view of the forward (away from the client, towards the exit) state of the circuit.
#[allow(unused)]
struct Forward {
    /// The circuit identifier on the forward Tor channel.
    circ_id: CircId,
    /// The sending end of the forward Tor channel.
    chan_sender: ChannelSender,
}

impl<T: HasRelayIds> ForwardReactor<T> {
    /// Create a new [`ForwardReactor`].
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        hop: CircHopInbound,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        outgoing_chan_rx: mpsc::UnboundedReceiver<ChannelResult>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
        cell_tx: mpsc::Sender<BackwardReactorCmd>,
        padding_ctrl: PaddingController,
        shutdown_rx: broadcast::Receiver<void::Void>,
    ) -> Self {
        Self {
            hop,
            unique_id,
            input,
            outgoing_chan_rx,
            crypto_out,
            // Initially, we are the last hop in the circuit.
            forward: None,
            chan_provider,
            cell_tx,
            padding_ctrl,
            shutdown_rx,
        }
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(super) async fn run(mut self) -> Result<()> {
        trace!(
            circ_id = %self.unique_id,
            "Running relay circuit reactor (forward subtask)",
        );

        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };

        // Log that the reactor stopped, possibly with the associated error as a report.
        // May log at a higher level depending on the error kind.
        const MSG: &str = "Relay circuit reactor (forward) stopped";
        match &result {
            Ok(()) => trace!("{}: {MSG}", self.unique_id),
            Err(e) => trace_report!(e, "{}: {}", self.unique_id, MSG),
        }

        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        let chan_sender_ready = future::poll_fn(|cx| {
            if let Some(forward) = self.forward.as_mut() {
                let _ = forward.chan_sender.poll_flush_unpin(cx);

                forward.chan_sender.poll_ready_unpin(cx)
            } else {
                // If there is no forward Tor channel, we're happy to read from input.
                // In fact, we *must* read from input, because the client might
                // have sent some Tor stream data.
                Poll::Ready(Ok(()))
            }
        });

        let input_fut = async {
            // Avoid polling the application streams if the outgoing sink is blocked
            let _ = chan_sender_ready.await;
            self.input.next().await
        };

        select_biased! {
            _res = self.shutdown_rx.next().fuse() => {
                trace!(
                    circ_id = %self.unique_id,
                    "Forward relay reactor shutdown (received shutdown signal)",
                );

                Err(ReactorError::Shutdown)
            }
            res = self.outgoing_chan_rx.next() => {
                let chan_res = res
                    // It's safe to expect here, because we always keep
                    // one sender alive in self
                    .expect("dropped self while self is still alive?!");

                self.handle_outgoing_chan_res(chan_res).await
            },
            cell = input_fut.fuse() => {
                let Some(cell) = cell else {
                    debug!(
                        circ_id = %self.unique_id,
                        "Backward channel has closed, shutting down forward relay reactor",
                    );

                    return Err(ReactorError::Shutdown);
                };

                // TODO: if the cell carries Tor stream data, this function will need to
                // send the cell to the BackwardReactor, to have it delivered
                // to the appropriate Tor stream
                self.handle_forward_cell(cell.try_into()?).await
            },
        }
    }

    /// Handle the outcome of our request to launch an outgoing Tor channel.
    ///
    /// If the request was successful, extend the circuit,
    /// and respond with EXTENDED to the client.
    ///
    /// if the request failed, we need to tear down the circuit.
    #[allow(unused)] // TODO(relay)
    #[allow(unreachable_code)] // TODO(relay)
    async fn handle_outgoing_chan_res(
        &mut self,
        chan_res: ChannelResult,
    ) -> StdResult<(), ReactorError> {
        let chan = match chan_res {
            Ok(chan) => chan,
            Err(e) => {
                warn_report!(e, "Failed to launch outgoing channel");
                // Note: retries are handled within
                // get_or_launch(), so if we receive an
                // error at this point, we need to bail

                // TODO(relay): we need to update our state
                // (should we send a DESTROY cell to tear down the circ?)
                return Ok(());
            }
        };

        if self.forward.is_some() {
            return Err(internal!("relay circuit has 2 outgoing channels?!").into());
        }

        // Now that we finally have a forward Tor channel,
        // it's time to forward the onion skin and extend the circuit...

        /* TODO(relay): the channel reactor's CircMap can only hold client circuit entries
        * We can address this TODO once #1599 is implemented
        *
        * let (sender, receiver) =
        *     MpscSpec::new(128).new_mq(self.runtime.clone(), memquota.as_raw_account())?;
        * let (createdsender, createdreceiver) = oneshot::channel::<CreateResponse>();

        * let (tx, rx) = oneshot::channel();
        * self.send_control(crate::channel::CtrlMsg::AllocateCircuit {
        *     created_sender: createdsender,
        *     sender,
        *     tx,
        * })?;

        * let (id, circ_id, padding_ctrl, padding_stream) =
        *     rx.await.map_err(|_| ChannelClosed)??;
        */

        // TODO(relay): the channel reactor doesn't support relay circuits
        // (the circuit entries from the CircMap use ClientCircChanMsg instead
        // of RelayCircChanMsg)
        let circ_id = todo!();
        let receiver = todo!();

        // TODO(relay): deliver `receiver` to the other reactor,
        // and instruct it to send back an EXTEND/EXTENDED2

        let forward = Forward {
            circ_id,
            chan_sender: chan.sender(),
        };

        self.forward = Some(forward);

        // TODO(relay): assuming the TODO above is addressed,
        // if we reach this point, it means we have extended
        // the circuit by one hop, so we need to take the contents
        // of the CREATE/CREATED2 cell, and package an EXTEND/EXTENDED2
        // to send back to the client.

        Ok(())
    }

    /// Handle a forward cell (moving from the client towards the exit).
    async fn handle_forward_cell(&mut self, cell: RelayCircChanMsg) -> StdResult<(), ReactorError> {
        use RelayCircChanMsg::*;

        match cell {
            Relay(r) => self.handle_relay_cell(r).await,
            RelayEarly(r) => self.handle_relay_early_cell(r),
            Destroy(d) => self.handle_destroy_cell(d),
            PaddingNegotiate(p) => self.handle_padding_negotiate(p),
        }
    }

    /// Handle a RELAY cell originating from the client.
    async fn handle_relay_cell(&mut self, cell: Relay) -> StdResult<(), ReactorError> {
        let cmd = cell.cmd();
        let mut body = cell.into_relay_body().into();
        let Some(tag) = self.crypto_out.decrypt_outbound(cmd, &mut body) else {
            // The message is not addressed to us, so we must relay it forward, towards the exit
            return self.send_msg_to_exit(body, None);
        };

        // The message is addressed to us! Now it's time to handle it...
        let decode_res = self.hop.decode(body.into())?;

        // TODO(relay): tell padding_ctrl we decrypted data or padding

        let c_t_w = decode_res.cmds().any(sendme::cmd_counts_towards_windows);

        // Decrement the circuit sendme windows, and see if we need to
        // send a sendme cell.
        let send_circ_sendme = if c_t_w {
            self.hop.ccontrol().note_data_received()?
        } else {
            false
        };

        // If we do need to send a circuit-level SENDME cell, do so.
        if send_circ_sendme {
            // This always sends a V1 (tagged) sendme cell, and thereby assumes
            // that SendmeEmitMinVersion is no more than 1.  If the authorities
            // every increase that parameter to a higher number, this will
            // become incorrect.  (Higher numbers are not currently defined.)
            let forward = BackwardReactorCmd::SendSendme(Sendme::from(tag));

            // NOTE: sending the SENDME to the backward reactor for handling
            // might seem counterintuitive, given that we have access to
            // the congestion control object right here
            // (CC state is shared between CircHopInbound and CircHopOutbound).
            //
            // However, the forward reactor does not have access to the
            // chan_sender part of the inbound (towards the client) Tor channel,
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
            match self.handle_relay_msg(msg, c_t_w).await {
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
        msg: UnparsedRelayMsg,
        cell_counts_toward_windows: bool,
    ) -> StdResult<(), ReactorError> {
        // If this msg wants/refuses to have a Stream ID, does it
        // have/not have one?
        let streamid = msg_streamid(&msg)?;

        // If this doesn't have a StreamId, it's a meta cell,
        // not meant for a particular stream.
        let Some(sid) = streamid else {
            return self.handle_meta_msg(msg).await;
        };

        // All messages on streams are handled in the backward reactor
        // (because that's where the stream map is)
        self.send_reactor_cmd(BackwardReactorCmd::HandleMsg {
            sid,
            msg,
            cell_counts_toward_windows,
        })
        .await
    }

    /// Handle a RELAY message on this circuit with stream ID 0.
    async fn handle_meta_msg(&mut self, msg: UnparsedRelayMsg) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::SENDME => {
                let sendme = msg
                    .decode::<Sendme>()
                    .map_err(|e| Error::from_bytes_err(e, "sendme message"))?
                    .into_msg();

                let forward = BackwardReactorCmd::HandleSendme(sendme);
                self.send_reactor_cmd(forward).await
            }
            RelayCmd::DROP => self.handle_drop(),
            RelayCmd::EXTEND2 => self.handle_extend2().await,
            RelayCmd::TRUNCATE => self.handle_truncate().await,
            _ => todo!(),
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
    async fn handle_extend2(&mut self) -> StdResult<(), ReactorError> {
        todo!()
    }

    /// Handle a TRUNCATE cell.
    async fn handle_truncate(&mut self) -> StdResult<(), ReactorError> {
        // TODO(relay): when we implement this, we should try to do better than C Tor:
        // if we have some cells queued for the next hop in the circuit,
        // we should try to flush them *before* tearing it down.
        //
        // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3487#note_3296035
        todo!()
    }

    /// Send a command to the backward reactor.
    ///
    /// Blocks if the `cell_tx` channel is full, i.e. if the backward reactor
    /// is not ready to send any more cells.
    ///
    /// Returns an error if the backward reactor has shut down.
    async fn send_reactor_cmd(
        &mut self,
        forward: BackwardReactorCmd,
    ) -> StdResult<(), ReactorError> {
        self.cell_tx.send(forward).await.map_err(|_| {
            // The other reactor has shut down
            ReactorError::Shutdown
        })
    }

    /// Send a RELAY cell with the specified `body` to the exit.
    fn send_msg_to_exit(
        &mut self,
        body: RelayCellBody,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError> {
        let Some(forward) = self.forward.as_mut() else {
            return Err(Error::CircProto(
                "Asked to forward cell, but there is no forward channel?!".into(),
            )
            .into());
        };

        let msg = Relay::from(BoxedCellBody::from(body));
        let relay = AnyChanMsg::Relay(msg);
        let cell = AnyChanCell::new(Some(forward.circ_id), relay);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the input channel, so await won't block.
        forward.chan_sender.start_send_unpin((cell, info))?;

        Ok(())
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
