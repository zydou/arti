//! A relay's view of the forward (away from the client, towards the exit) state of the circuit.

use crate::channel::ChannelSender;
use crate::circuit::UniqId;
use crate::circuit::celltypes::RelayCircChanMsg;
use crate::circuit::circhop::CircHopInbound;
use crate::crypto::cell::{OutboundRelayLayer, RelayCellBody};
use crate::relay::channel_provider::{ChannelProvider, ChannelResult};
use crate::util::err::ReactorError;
use crate::{Error, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;

use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::msg::{Destroy, PaddingNegotiate, Relay, RelayEarly};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanMsg, CircId};
use tor_cell::relaycell::StreamId;
use tor_cell::relaycell::msg::AnyRelayMsg;
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
/// Shuts downs down if an error occurs, or if either the [`RelayReactor`](super::RelayReactor)
/// or the [`BackwardReactor`](super::BackwardReactor) shuts down:
///
///   * if `RelayReactor` shuts down, we are alerted via the `shutdown_tx` broadcast channel
///     (we will notice this its closure in the main loop)
///   * if `BackwardReactor` shuts down, `RelayReactor` will notice, and itself shutdown
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
    /// Sender for RELAY cells that need to be forwarded to the client.
    ///
    /// The receiver is in [`BackwardReactor`](super::BackwardReactor), which is responsible for all
    /// sending all client-bound cells.
    cell_tx: mpsc::UnboundedSender<(StreamId, AnyRelayMsg)>,
    /// A handle to a [`ChannelProvider`], used for initiating outgoing Tor channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying Tor channel provider (`ChanMgr`),
    /// to enable the reuse of existing Tor channels where possible.
    chan_provider: Box<dyn ChannelProvider<BuildSpec = T> + Send>,
    /// A broadcast receiver used to detect when the
    /// [`RelayReactor`](super::RelayReactor) or
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
        cell_tx: mpsc::UnboundedSender<(StreamId, AnyRelayMsg)>,
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
                self.handle_forward_cell(cell).await
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
                // get_or_launch_relay(), so if we receive an
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
        if let Some(_tag) = self.crypto_out.decrypt_outbound(cmd, &mut body) {
            // The message is addressed to us! Now it's time to handle it...
            let _decode_res = self.hop.decode(body.into())?;

            // TODO: actually handle the cell
            // TODO: if the message is recognized, it may need to be delivered
            // to the BackwardReactor via the cell_tx channel for handling
            // (because e.g. Tor stream data is handled in the BackwardReactor)
        } else {
            // The message is not addressed to us, so we must relay it forward, towards the exit
            self.send_msg_to_exit(body, None)?;
        }

        Ok(())
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
