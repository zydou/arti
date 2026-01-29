//! Module exposing the relay circuit reactor subsystem.
//!
//! See [`reactor`](crate::circuit::reactor) for a description of the overall architecture.
//!
//! #### `ForwardReactor`
//!
//! It handles
//!
//!  * unrecognized RELAY cells, by moving them in the forward direction (towards the exit)
//!  * recognized RELAY cells, by splitting each cell into messages, and handling
//!    each message individually as described in the table below
//!    (Note: since prop340 is not yet implemented, in practice there is only 1 message per cell).
//!  * RELAY_EARLY cells (**not yet implemented**)
//!  * DESTROY cells (**not yet implemented**)
//!  * PADDING_NEGOTIATE cells (**not yet implemented**)
//!
//! ```text
//!
//! Legend: `F` = "forward reactor", `B` = "backward reactor", `S` = "stream reactor"
//!
//! | RELAY cmd         | Received in | Handled in | Description                            |
//! |-------------------|-------------|------------|----------------------------------------|
//! | DROP              | F           | F          | Passed to PaddingController for        |
//! |                   |             |            | validation                             |
//! |-------------------|-------------|------------|----------------------------------------|
//! | EXTEND2           | F           |            | Handled by instructing the channel     |
//! |                   |             |            | provider to launch a new channel, and  |
//! |                   |             |            | waiting for the new channel on its     |
//! |                   |             |            | outgoing_chan_rx receiver              |
//! |                   |             |            | (**not yet implemented**)              |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TRUNCATE          | F           | F          | (**not yet implemented**)              |
//! |                   |             |            |                                        |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TODO              |             |            |                                        |
//! |                   |             |            |                                        |
//! ```

pub(crate) mod backward;
pub(crate) mod forward;

use std::sync::Arc;

use futures::channel::mpsc;

use tor_cell::chancell::CircId;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::Runtime;

use crate::channel::Channel;
use crate::circuit::circhop::HopSettings;
use crate::circuit::reactor::Reactor as BaseReactor;
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::CircuitAccount;
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::backward::Backward;
use crate::relay::reactor::forward::Forward;
use crate::util::timeout::TimeoutEstimator;

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, PaddingEventStream};

/// Type-alias for the relay base reactor type.
type RelayBaseReactor<R> = BaseReactor<R, Forward, Backward>;

/// The entry point of the circuit reactor subsystem.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct Reactor<R: Runtime>(RelayBaseReactor<R>);

#[allow(unused)] // TODO(relay)
impl<R: Runtime> Reactor<R> {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::too_many_arguments)] // TODO
    pub(super) fn new(
        runtime: R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        settings: &HopSettings,
        chan_provider: Box<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        timeouts: Arc<dyn TimeoutEstimator>,
        memquota: &CircuitAccount,
    ) -> crate::Result<(Self, Arc<RelayCirc>)> {
        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        #[allow(clippy::disallowed_methods)]
        let (stream_tx, stream_rx) = mpsc::channel(0);

        let mut hop_mgr = HopMgr::new(
            runtime.clone(),
            unique_id,
            timeouts,
            stream_tx,
            memquota.clone(),
        );

        // On the relay side, we always have one "hop" (ourselves).
        //
        // Clients will need to call this function in response to CtrlMsg::Create
        // (TODO: for clients, we probably will need to store a bunch more state here)
        hop_mgr.add_hop(settings.clone())?;

        let forward_foo = Forward::new(crypto_out);
        let backward_foo = Backward::new(crypto_in);

        let (inner, handle) = crate::circuit::reactor::Reactor::new(
            runtime,
            channel,
            circ_id,
            unique_id,
            input,
            forward_foo,
            backward_foo,
            hop_mgr,
            padding_ctrl,
            padding_event_stream,
            stream_rx,
            memquota,
            chan_provider,
        );

        let reactor = Self(inner);
        let handle = Arc::new(RelayCirc(handle));

        Ok((reactor, handle))
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> crate::Result<()> {
        self.0.run().await
    }
}
