//! Handler for EXTEND2 cells.

use super::{CircEvent, ExtendResult, Outbound};

use crate::Error;
use crate::circuit::UniqId;
use crate::circuit::create::{Create2Wrap, CreateHandshakeWrap};
use crate::peer::PeerInfo;
use crate::relay::channel_provider::{ChannelProvider, ChannelResult, OutboundChanSender};
use crate::relay::reactor::CircuitAccount;
use crate::util::err::ReactorError;
use tor_cell::chancell::AnyChanCell;
use tor_cell::relaycell::UnparsedRelayMsg;
use tor_cell::relaycell::msg::{Extend2, Extended2};
use tor_error::{internal, into_internal, warn_report};
use tor_linkspec::decode::Strictness;
use tor_linkspec::{HasRelayIds, OwnedChanTarget, OwnedChanTargetBuilder};
use tor_rtcompat::{Runtime, SpawnExt as _};

use futures::channel::mpsc;
use futures::{SinkExt as _, StreamExt as _};
use tracing::{debug, trace};

use std::result::Result as StdResult;
use std::sync::Arc;

/// Helper for handling EXTEND2 cells.
pub(super) struct ExtendRequestHandler {
    /// An identifier for logging about this handler.
    unique_id: UniqId,
    /// Whether we have received an EXTEND2 on this circuit.
    ///
    // TODO(relay): bools can be finicky.
    // Maybe we should combine this bool and the optional
    // outbound into a new state machine type
    // (with states Initial -> Extending -> Extended(Outbound))?
    // But should not do this if it turns out more convoluted than the bool-based approach.
    have_seen_extend2: bool,
    /// A handle to a [`ChannelProvider`], used for initiating outgoing Tor channels.
    ///
    /// Note: all circuit reactors of a relay need to be initialized
    /// with the *same* underlying Tor channel provider (`ChanMgr`),
    /// to enable the reuse of existing Tor channels where possible.
    chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
    /// The identity of the inbound relay (the previous hop).
    inbound_peer: PeerInfo,
    /// A stream of events to be read from the main loop of the reactor.
    event_tx: mpsc::Sender<CircEvent>,
    /// Memory quota account
    memquota: CircuitAccount,
}

impl ExtendRequestHandler {
    /// Create a new [`ExtendRequestHandler`].
    pub(super) fn new(
        unique_id: UniqId,
        chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
        inbound_peer: PeerInfo,
        event_tx: mpsc::Sender<CircEvent>,
        memquota: CircuitAccount,
    ) -> Self {
        Self {
            unique_id,
            have_seen_extend2: false,
            chan_provider,
            inbound_peer,
            event_tx,
            memquota,
        }
    }

    /// Handle an EXTEND2 cell.
    ///
    /// This spawns a background task for dealing with the circuit extension,
    /// which then reports back the result via the [`Self::event_tx`] MPSC stream.
    /// Note that this MPSC stream is polled from the `ForwardReactor` main loop,
    /// and each `CircEvent` is passed back to [`Forward`](super::Forward)'s
    /// [`ForwardHandler::handle_event`](crate::circuit::reactor::forward::ForwardHandler::handle_event)
    /// implementation for handling.
    pub(super) fn handle_extend2<R: Runtime>(
        &mut self,
        runtime: &R,
        early: bool,
        msg: UnparsedRelayMsg,
    ) -> StdResult<(), ReactorError> {
        // TODO(relay): this should be allowed if the AllowNonearlyExtend consensus
        // param is set (arti#2349)
        if !early {
            return Err(Error::CircProto("got EXTEND2 in a RELAY cell?!".into()).into());
        }

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

        if chan_target.has_any_relay_id_from(&self.inbound_peer) {
            return Err(Error::CircProto("Cannot extend circuit to previous hop".into()).into());
        }

        // Note: we don't do any further validation on the EXTEND2 here,
        // under the assumption it will be handled by the ChannelProvider.

        let (chan_tx, chan_rx) = mpsc::unbounded();

        let chan_tx = OutboundChanSender(chan_tx);
        Arc::clone(&self.chan_provider).get_or_launch(self.unique_id, chan_target, chan_tx)?;

        let mut result_tx = self.event_tx.clone();
        let rt = runtime.clone();
        let unique_id = self.unique_id;
        let memquota = self.memquota.clone();

        // TODO(relay): because we dispatch this the entire EXTEND2 handling to a background task,
        // we don't really need the channel provider to send us the outcome via an MPSC channel,
        // because get_or_launch() could simply be async (it wouldn't block the reactor,
        // because it runs in another task). Maybe we need to rethink the ChannelProvider API?
        runtime
            .spawn(async move {
                let res = Self::extend_circuit(rt, unique_id, extend2, chan_rx, memquota).await;

                // Discard the error if the reactor shut down before we had
                // a chance to complete the extend handshake
                let _ = result_tx.send(CircEvent::ExtendResult(res)).await;
            })
            .map_err(into_internal!("failed to spawn extend task?!"))?;

        Ok(())
    }

    /// Extend this circuit on the channel received on `chan_rx`.
    ///
    /// Note: this gets spawned in a background task from
    /// [`Self::handle_extend2`] so as not to block the reactor main loop.
    async fn extend_circuit<R: Runtime>(
        _runtime: R,
        unique_id: UniqId,
        extend2: Extend2,
        mut chan_rx: mpsc::UnboundedReceiver<ChannelResult>,
        memquota: CircuitAccount,
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

        debug!(
            circ_id = %unique_id,
            "Launched channel to the next hop"
        );

        // Now that we finally have a forward Tor channel,
        // it's time to forward the onion skin and extend the circuit...
        //
        // Note: the only reason we need to await here is because internally
        // new_outbound_circ() sends a control message to the channel reactor handles,
        // which is handled asynchronously. In practice, we're not actually waiting on
        // the network here, so in theory we shouldn't need a timeout for this operation.
        let (circ_id, outbound_chan_rx, createdreceiver) =
            channel.new_outbound_circ(memquota).await?;

        // We have allocated a circuit in the channel's circmap,
        // now it's time to send the CREATE2 and wait for the response.
        let create2_wrap = Create2Wrap {
            handshake_type: extend2.handshake_type(),
        };
        let create2 = create2_wrap.to_chanmsg(extend2.handshake().into());

        // Time to write the CREATE2 to the outbound channel...
        let mut outbound_chan_tx = channel.sender();
        let cell = AnyChanCell::new(Some(circ_id), create2);

        trace!(
            circ_id = %unique_id,
            "Sending CREATE2 to the next hop"
        );

        outbound_chan_tx.send((cell, None)).await?;

        // TODO(relay): we need a timeout here, otherwise we might end up waiting forever
        // for the CREATED2 to arrive.
        //
        // There is some complexity here, see
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3648#note_3340125
        let response = createdreceiver
            .await
            .map_err(|_| internal!("channel disappeared?"))?;

        trace!(
            circ_id = %unique_id,
            "Got CREATED2 response from next hop"
        );

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
}
