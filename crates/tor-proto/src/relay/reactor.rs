//! Module exposing the relay circuit reactor.

use crate::DynTimeProvider;
use crate::Result;
use crate::channel::Channel;
use crate::circuit::UniqId;
use crate::memquota::CircuitAccount;
use crate::tunnel::{TunnelId, TunnelScopedCircId};
use crate::util::err::ReactorError;

use tor_cell::chancell::CircId;
use tor_error::{trace_report, warn_report};
use tor_linkspec::HasRelayIds;

use futures::channel::mpsc;
use futures::{StreamExt, select_biased};
use oneshot_fused_workaround as oneshot;
use tracing::trace;

use std::result::Result as StdResult;
use std::sync::Arc;

use crate::client::reactor::unwrap_or_shutdown;
use crate::relay::channel_provider::{ChannelProvider, ChannelResult};

/// A message telling the reactor to do something.
///
/// For each `RelayCtrlMsg`, the reactor will send a cell on the underlying channel.
///
/// The difference between this and [`RelayCtrlCmd`] is that `RelayCtrlMsg`s
/// cause the reactor to send cells on the reactor's `chan_sender`,
/// whereas `RelayCtrlCmd` do not.
///
// TODO(relay): we may not need this
#[allow(unused)] // TODO(relay)
pub(crate) enum RelayCtrlMsg {}

/// A message telling the reactor to do something.
///
/// The difference between this and [`RelayCtrlMsg`] is that `RelayCtrlCmd`s
/// never cause cells to sent on the channel,
/// while `RelayCtrlMsg`s potentially do.
//
// TODO(relay): we may not need this
#[derive(educe::Educe)]
#[educe(Debug)]
#[allow(unused)] // TODO(relay)
pub(crate) enum RelayCtrlCmd {
    /// Shut down the reactor.
    Shutdown,
}

/// The circuit reactor of a relay.
///
// TODO(relay): docs
//
// NOTE: the reactor is currently a bit awkward, because it's generic over
// the target relay `BuildSpec`. This will become slightly less awkward when
// we refactor this and the client circuit reactor to be based on an abstract
// reactor type.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct RelayReactor<T: HasRelayIds> {
    /// Receiver for control messages for this reactor, sent by reactor handle objects.
    control: mpsc::UnboundedReceiver<RelayCtrlMsg>,
    /// Receiver for command messages for this reactor, sent by reactor handle objects.
    ///
    /// This channel is polled in [`RelayReactor::run_once`].
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<RelayCtrlCmd>,
    /// A handle to a [`ChannelProvider`], used for initiating outgoing channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying channel provider (`ChanMgr`),
    /// to enable the reuse of existing channels where possible.
    chan_provider: Box<dyn ChannelProvider<BuildSpec = T>>,
    /// A sender for sending newly opened outgoing [`Channel`]`s to the reactor.
    ///
    /// This is passed to the [`ChannelProvider`] for each channel request.
    outgoing_chan_tx: mpsc::UnboundedSender<ChannelResult>,
    /// A channel for receiving newly opened outgoing [`Channel`]s.
    ///
    /// This channel is polled from the main loop of the reactor,
    /// and is used for updating the outgoing channel map.
    //
    // TODO(relay): implement an outgoing channel map
    outgoing_chan_rx: mpsc::UnboundedReceiver<ChannelResult>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: oneshot::Sender<void::Void>,
    /// An identifier for logging about this reactor.
    tunnel_id: TunnelId,
    /// The time provider.
    runtime: DynTimeProvider,
}

/// A handle for interacting with a [`RelayReactor`].
#[allow(unused)] // TODO(relay)
pub(crate) struct RelayReactorHandle {
    /// Sender for reactor control messages.
    control: mpsc::UnboundedSender<RelayCtrlMsg>,
    /// Sender for reactor control commands.
    command: mpsc::UnboundedSender<RelayCtrlCmd>,
    /// A oneshot receiver used to detect when the reactor is dropped.
    reactor_closed_rx: oneshot::Receiver<void::Void>,
}

#[allow(unused)] // TODO(relay)
impl<T: HasRelayIds> RelayReactor<T> {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        runtime: DynTimeProvider,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = T>>,
        memquota: CircuitAccount,
    ) -> (Self, RelayReactorHandle) {
        let tunnel_id = TunnelId::next();
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let (outgoing_chan_tx, outgoing_chan_rx) = mpsc::unbounded();

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let unique_id = TunnelScopedCircId::new(tunnel_id, unique_id);

        let reactor = Self {
            control: control_rx,
            command: command_rx,
            chan_provider,
            outgoing_chan_tx,
            outgoing_chan_rx,
            reactor_closed_tx,
            tunnel_id,
            runtime,
        };

        let handle = RelayReactorHandle {
            control: control_tx,
            command: command_tx,
            reactor_closed_rx,
        };

        (reactor, handle)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> Result<()> {
        trace!(
            tunnel_id = %self.tunnel_id,
            "Running relay circuit reactor",
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
        const MSG: &str = "Relay circuit reactor stopped";
        match &result {
            Ok(()) => trace!("{}: {MSG}", self.tunnel_id),
            Err(e) => trace_report!(e, "{}: {}", self.tunnel_id, MSG),
        }

        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        // TODO(relay): implement
        let () = select_biased! {
            res = self.command.next() => {
                let _cmd = unwrap_or_shutdown!(self, res, "command channel drop")?;
            },
            res = self.control.next() => {
                let _msg = unwrap_or_shutdown!(self, res, "control drop")?;
            },
            res = self.outgoing_chan_rx.next() => {
                let chan_res = res
                    // It's safe to expect here, because we always keep
                    // one sender alive in self
                    .expect("dropped self while self is still alive?!");

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

                // TODO(relay): we have a new channel,
                // we need to update our state and respond to the initiator
                // (e.g. we might need to send back an EXTENDED2 cell)
            }
        };

        Ok(())
    }
}
