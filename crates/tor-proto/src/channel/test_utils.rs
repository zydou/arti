//! Utilities and helpers for testing channels.

// These are test utilities.
#![allow(clippy::unwrap_used)]

use futures::channel::mpsc;
use futures::{SinkExt as _, StreamExt as _};
use safelog::MaybeSensitive;
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;
use tor_cell::chancell::AnyChanCell;
use tor_key_forge::Keygen as _;
use tor_linkspec::{
    HasRelayIds as _, OwnedChanTarget, OwnedCircTarget, OwnedCircTargetBuilder, RelayIds,
    RelayIdsBuilder,
};
use tor_rtcompat::{NoOpStreamOpsHandle, Runtime, SpawnExt as _};

use crate::ClockSkew;
use crate::channel::circmap::CircIdRange;
use crate::channel::{
    BoxedChannelSink, BoxedChannelStream, Canonicity, Channel, ChannelMode, Reactor, UniqId,
};
use crate::client::circuit::{PendingClientTunnel, TimeoutEstimator};
use crate::memquota::{ChannelAccount, SpecificAccount};
use crate::peer::{PeerAddr, PeerInfo};

#[cfg(feature = "relay")]
use {
    crate::relay::CreateRequestHandler,
    crate::relay::channel_provider::{ChannelProvider, NoOpChannelProvider},
    crate::relay::{CircNetParameters, CircuitIncomingStreamReceiver, CongestionControlNetParams},
    crate::stream::incoming::NoOpRequestFilter,
    tor_relay_crypto::pk::RelayNtorKeys,
};

/// Construct a new channel and its reactor.
pub(crate) fn new_channel<R: Runtime>(
    rt: &R,
    mode: ChannelMode,
    peer_info: PeerInfo,
    sender: BoxedChannelSink,
    receiver: BoxedChannelStream,
) -> (Arc<Channel>, Reactor<R>) {
    let mut peer_id = OwnedChanTarget::builder();
    *peer_id.ids() = RelayIdsBuilder::from_relay_ids(&peer_info);
    let peer_id = peer_id.build().unwrap();

    // The only link protocol that Arti currently supports.
    // This is hardcoded to '4' throughout the rest of tor-proto.
    let link_protocol = 4;
    let clock_skew = ClockSkew::None;
    let canonicity = Canonicity {
        peer_is_canonical: true,
        canonical_to_peer: true,
    };
    let memquota = ChannelAccount::new_noop();

    let (chan, reactor) = Channel::new(
        mode,
        link_protocol,
        sender,
        receiver,
        Box::new(NoOpStreamOpsHandle::default()),
        UniqId::new(),
        peer_id,
        MaybeSensitive::not_sensitive(peer_info),
        clock_skew,
        rt.clone(),
        memquota,
        canonicity,
    )
    .unwrap();

    (chan, reactor)
}

/// Initialize connected client and relay channels.
///
/// Returns a client channel and a relay channel respectively.
///
/// The [`ConnInspector`] allows you to inspect the cells that they send to each other.
#[cfg(feature = "relay")]
pub(crate) fn new_channel_pair<R: Runtime>(
    rt: &R,
    chan_provider: Weak<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
    relay_ids: RelayIds,
    relay_ntor_keys: RelayNtorKeys,
    conn_inspector: &ConnInspector,
) -> (Arc<Channel>, Arc<Channel>, CircuitIncomingStreamReceiver) {
    let relay_info = PeerInfo::new(PeerAddr::UNSPECIFIED, relay_ids);
    let client_info = PeerInfo::new(PeerAddr::UNSPECIFIED, RelayIds::empty());

    let circ_net_params = CircNetParameters {
        cc: CongestionControlNetParams::defaults_for_tests(),
    };

    // A handler that will process CREATE* requests on channels.
    let (create_request_handler, circuit_stream_rx) = CreateRequestHandler::new(
        chan_provider,
        circ_net_params,
        relay_ntor_keys,
        // Don't filter any stream requests.
        Box::new(|| Box::new(NoOpRequestFilter) as Box<_>),
        // Don't allow any stream commands.
        &[],
    );
    let create_request_handler = Arc::new(create_request_handler);

    let client_mode = ChannelMode::Client;
    let relay_mode = ChannelMode::Relay {
        create_request_handler,
        our_ed25519_id: *relay_info.ed_identity().unwrap(),
        our_rsa_id: *relay_info.rsa_identity().unwrap(),
        // The relay is the responder.
        circ_id_range: CircIdRange::Low,
    };

    // This simplifies the rustc errors when something goes wrong.
    // c_to_r = client -> relay
    // r_to_c = relay -> client
    let c_to_r_tx: mpsc::Sender<AnyChanCell>;
    let r_to_c_tx: mpsc::Sender<AnyChanCell>;
    let c_to_r_rx: mpsc::Receiver<AnyChanCell>;
    let r_to_c_rx: mpsc::Receiver<AnyChanCell>;

    (c_to_r_tx, c_to_r_rx) = mpsc::channel(32);
    (r_to_c_tx, r_to_c_rx) = mpsc::channel(32);

    // `BoxedChannelStream` requires `Item = Result<AnyChanCell, _>`.
    let c_to_r_rx = c_to_r_rx.map(Ok);
    let r_to_c_rx = r_to_c_rx.map(Ok);

    // `BoxedChannelSink` requires `Error = crate::Error`.
    let c_to_r_tx = c_to_r_tx.sink_map_err(|e| crate::Error::CellDecodeErr {
        object: "reactor test",
        err: tor_cell::Error::ChanProto(format!("Sink error: {e:?}")),
    });
    let r_to_c_tx = r_to_c_tx.sink_map_err(|e| crate::Error::CellDecodeErr {
        object: "reactor test",
        err: tor_cell::Error::ChanProto(format!("Sink error: {e:?}")),
    });

    // We want to clone cells that the client channel or relay channel sends,
    // and store a copy in the connection inspector.
    let client_inspector_tx = conn_inspector.client_inspector_tx.clone();
    let c_to_r_tx = c_to_r_tx.with(move |cell: AnyChanCell| {
        let client_inspector_tx = client_inspector_tx.clone();
        async move {
            let (cell, cell_clone) = clone_chan_cell(cell);
            let _ = client_inspector_tx.unbounded_send(cell_clone);
            Ok(cell)
        }
    });
    let c_to_r_tx = Box::pin(c_to_r_tx);

    let relay_inspector_tx = conn_inspector.relay_inspector_tx.clone();
    let r_to_c_tx = r_to_c_tx.with(move |cell: AnyChanCell| {
        let relay_inspector_tx = relay_inspector_tx.clone();
        async move {
            let (cell, cell_clone) = clone_chan_cell(cell);
            let _ = relay_inspector_tx.unbounded_send(cell_clone);
            Ok(cell)
        }
    });
    let r_to_c_tx = Box::pin(r_to_c_tx);

    // The `Channel` requires these to be boxed trait objects.
    let (c_to_r_tx, c_to_r_rx) = (Box::new(c_to_r_tx), Box::new(c_to_r_rx));
    let (r_to_c_tx, r_to_c_rx) = (Box::new(r_to_c_tx), Box::new(r_to_c_rx));

    let (client_chan, client_reactor) =
        new_channel(rt, client_mode, relay_info, c_to_r_tx, r_to_c_rx);

    let (relay_chan, relay_reactor) =
        new_channel(rt, relay_mode, client_info, r_to_c_tx, c_to_r_rx);

    rt.spawn(async {
        let _ = futures::future::join(client_reactor.run(), relay_reactor.run()).await;
    })
    .unwrap();

    (client_chan, relay_chan, circuit_stream_rx)
}

/// Initialize connected client and relay channels with pre-generated keys.
///
/// Returns a client channel and a relay channel respectively, and a partially built
/// [`OwnedCircTarget`] that can be used to build circuits.
///
/// The [`ConnInspector`] allows you to inspect the cells that they send to each other.
#[cfg(feature = "relay")]
pub(crate) fn new_channel_pair_with_keys<R: Runtime>(
    rt: &R,
    conn_inspector: &ConnInspector,
) -> (
    Arc<Channel>,
    Arc<Channel>,
    CircuitIncomingStreamReceiver,
    OwnedCircTargetBuilder,
) {
    let mut rng = tor_llcrypto::rng::CautiousRng;

    // Keys are chosen arbitrarily.
    let relay_ids = RelayIds::builder()
        .ed_identity([6_u8; 32].into())
        .rsa_identity([10_u8; 20].into())
        .build()
        .unwrap();

    let relay_ntor_keys = tor_llcrypto::pk::curve25519::StaticKeypair::generate(&mut rng).unwrap();
    let relay_ntor_keys = RelayNtorKeys::new(relay_ntor_keys.into());

    // Since channels only take a `Weak`, it means we need to keep the `Arc` around.
    // This is just a test and the channel provider is a no-op,
    // so keep a global around forever so that we can forget about it.
    static CHAN_PROVIDER: LazyLock<Arc<NoOpChannelProvider>> =
        LazyLock::new(|| Arc::new(NoOpChannelProvider));
    let chan_provider = Arc::downgrade(&CHAN_PROVIDER);

    let (client_chan, relay_chan, circuit_stream_rx) = new_channel_pair(
        rt,
        chan_provider,
        relay_ids.clone(),
        relay_ntor_keys.clone(),
        conn_inspector,
    );

    let mut target_builder = OwnedCircTarget::builder();
    target_builder.ntor_onion_key(*relay_ntor_keys.latest().public().inner());
    *target_builder.chan_target().ids() = RelayIdsBuilder::from_relay_ids(&relay_ids);

    (client_chan, relay_chan, circuit_stream_rx, target_builder)
}

/// Create a new [`PendingClientTunnel`] and start its reactor.
pub(crate) async fn new_pending_tunnel<R: Runtime>(
    rt: &R,
    channel: &Arc<Channel>,
) -> PendingClientTunnel {
    struct Timeouts;

    impl TimeoutEstimator for Timeouts {
        fn circuit_build_timeout(&self, _length: usize) -> Duration {
            // Chosen arbitrarily.
            Duration::from_secs(60)
        }
    }

    let (pending_tunnel, reactor) = channel.new_tunnel(Arc::new(Timeouts)).await.unwrap();

    rt.spawn(async {
        let _ = reactor.run().await;
    })
    .unwrap();

    pending_tunnel
}

/// Clone a `ChanCell`.
///
/// This is a hack since `ChanCell` doesn't implement `Clone`.
#[cfg(feature = "relay")]
fn clone_chan_cell(cell: AnyChanCell) -> (AnyChanCell, AnyChanCell) {
    let (circ_id, msg) = cell.into_circid_and_msg();

    let cell_1 = AnyChanCell::new(circ_id, msg.clone());
    let cell_2 = AnyChanCell::new(circ_id, msg);

    (cell_1, cell_2)
}

/// Inspect the cells transitting a connection between two channel objects
/// corresponding to a client and a relay.
#[cfg(feature = "relay")]
pub(crate) struct ConnInspector {
    /// Cells from the client to relay.
    client_inspector_tx: mpsc::UnboundedSender<AnyChanCell>,
    client_inspector_rx: mpsc::UnboundedReceiver<AnyChanCell>,

    /// Cells from the relay to client.
    relay_inspector_tx: mpsc::UnboundedSender<AnyChanCell>,
    relay_inspector_rx: mpsc::UnboundedReceiver<AnyChanCell>,
}

#[cfg(feature = "relay")]
impl ConnInspector {
    /// A new [`ConnInspector`].
    pub(crate) fn new() -> Self {
        let (client_inspector_tx, client_inspector_rx) = mpsc::unbounded();
        let (relay_inspector_tx, relay_inspector_rx) = mpsc::unbounded();

        ConnInspector {
            client_inspector_tx,
            client_inspector_rx,
            relay_inspector_tx,
            relay_inspector_rx,
        }
    }

    /// Try to get the next message sent by the client.
    pub(crate) fn try_client_cell(&mut self) -> Option<AnyChanCell> {
        self.client_inspector_rx.try_recv().ok()
    }

    /// Try to get the next message sent by the relay.
    pub(crate) fn try_relay_cell(&mut self) -> Option<AnyChanCell> {
        self.relay_inspector_rx.try_recv().ok()
    }

    /// Wait for the next message sent by the client.
    pub(crate) async fn client_cell(&mut self) -> Option<AnyChanCell> {
        self.client_inspector_rx.recv().await.ok()
    }

    /// Wait for the next message sent by the relay.
    pub(crate) async fn relay_cell(&mut self) -> Option<AnyChanCell> {
        self.relay_inspector_rx.recv().await.ok()
    }
}
