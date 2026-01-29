//! Channel for sending messages to [`StreamReactor`].

use crate::circuit::UniqId;
use crate::circuit::circhop::{CircHopOutbound, HopSettings};
use crate::circuit::reactor::circhop::CircHopList;
use crate::circuit::reactor::stream::{ReadyStreamMsg, StreamMsg, StreamReactor};
use crate::congestion::CongestionControl;
use crate::memquota::CircuitAccount;
use crate::util::err::ReactorError;
use crate::util::timeout::TimeoutEstimator;
use crate::{Error, HopNum, Result};

#[cfg(any(feature = "hs-service", feature = "relay"))]
use crate::stream::incoming::IncomingStreamRequestHandler;

use tor_error::internal;
use tor_rtcompat::Runtime;

use futures::SinkExt;
use futures::channel::mpsc;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex, RwLock};

/// The hop manager of a reactor.
///
/// This contains the per-hop state (e.g. congestion control information),
/// and a handle to the stream reactor of the hop.
///
/// The stream reactor of the hop is launched lazily,
/// when the first [`StreamMsg`] is sent via [`HopMgr::send`].
pub(crate) struct HopMgr<R: Runtime> {
    /// A handle to the runtime.
    runtime: R,
    /// Context used when spawning a stream reactor.
    ctx: StreamReactorContext,
    /// Sender for sending messages to BWD.
    ///
    /// The receiver is in BWD.
    ///
    /// A clone of this is passed to each spawned StreamReactor
    bwd_tx: mpsc::Sender<ReadyStreamMsg>,
    /// The underlying senders, indexed by [`HopNum`].
    ///
    /// Relays have at most one stream reactor per circuit.
    /// Clients have at most one stream reactor per circuit hop.
    ///
    /// This is shared with the backward reactor.
    /// The backward reactor only ever *reads* from this
    /// (it never mutates the list).
    ///
    // TODO: the backward reactor only ever reads from this.
    // Conceptually, it is the HopMgr that owns this list,
    // because only HopMgr can add hops to the list.
    //
    // Perhaps we need a specialized abstraction that only allows reading here.
    // This could be a wrapper over RwLock, providing a read-only API for the BWD.
    hops: Arc<RwLock<CircHopList>>,
    /// Memory quota account
    memquota: CircuitAccount,
}

/// State needed to build a stream reactor.
///
/// Used when spawning the stream reactor of a hop.
struct StreamReactorContext {
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The incoming stream handler.
    ///
    /// This is shared with every StreamReactor.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    incoming: Arc<Mutex<Option<IncomingStreamRequestHandler>>>,
    /// The circuit timeout estimator.
    ///
    /// Used for computing half-stream expiration.
    timeouts: Arc<dyn TimeoutEstimator>,
}

impl<R: Runtime> HopMgr<R> {
    /// Create a new [`HopMgr`] with an empty hop list.
    ///
    /// Hops are added with [`HopMgr::add_hop`].
    pub(crate) fn new(
        runtime: R,
        unique_id: UniqId,
        timeouts: Arc<dyn TimeoutEstimator>,
        bwd_tx: mpsc::Sender<ReadyStreamMsg>,
        memquota: CircuitAccount,
    ) -> Self {
        // We don't spawn any stream reactors ahead of time.
        // Instead we spawn them lazily, when opening streams.
        let hops = Arc::new(RwLock::new(Default::default()));
        let ctx = StreamReactorContext {
            unique_id,
            #[cfg(any(feature = "hs-service", feature = "relay"))]
            incoming: Arc::new(Mutex::new(None)),
            timeouts,
        };

        Self {
            runtime,
            hops,
            ctx,
            bwd_tx,
            memquota,
        }
    }

    /// Return a reference to our hop list.
    pub(crate) fn hops(&self) -> &Arc<RwLock<CircHopList>> {
        &self.hops
    }

    /// Set the incoming stream handler for this reactor.
    ///
    /// There can only be one incoming stream handler per reactor,
    /// and each stream handler only pertains to a single hop (see expected_hop())
    //
    // TODO: eventually, we might want a different design here,
    // for example we might want to allow multiple stream handlers per reactor (one per hop).
    // However, for now, the implementation is intentionally kept similar to that
    // in the client reactor (to make it easier to migrate it to the new reactor design).
    //
    /// Returns an error if the hop manager already has a stream handler.
    ///
    /// Since the handler is shared with every hop's stream reactor,
    /// this function will update the handler for all of them.
    ///
    // TODO(DEDUP): almost identical to the client-side
    // CellHandlers::set_incoming_stream_req_handler()
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    pub(crate) fn set_incoming_handler(&self, handler: IncomingStreamRequestHandler) -> Result<()> {
        let mut lock = self.ctx.incoming.lock().expect("poisoned lock");

        if lock.is_none() {
            *lock = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a BEGIN cell handler before the old one was gone."
            )))
        }
    }

    /// Push a new hop to our hop list.
    ///
    /// Prepares a cc object for the hop, but does not spawn a stream reactor.
    ///
    /// Will return an error if the circuit already has [`u8::MAX`] hops.
    pub(crate) fn add_hop(&mut self, settings: HopSettings) -> Result<()> {
        let mut hops = self.hops.write().expect("poisoned lock");
        hops.add_hop(settings)
    }

    /// Send a message to the stream reactor of the specified `hop`,
    /// spawning it if necessary.
    pub(crate) async fn send(
        &mut self,
        hopnum: Option<HopNum>,
        msg: StreamMsg,
    ) -> StdResult<(), ReactorError> {
        let mut tx = self.get_or_spawn_stream_reactor(hopnum)?;

        tx.send(msg).await.map_err(|_| {
            // The stream reactor has shut down
            ReactorError::Shutdown
        })
    }

    /// Get a handle to the stream reactor, spawning it if necessary
    fn get_or_spawn_stream_reactor(
        &self,
        hopnum: Option<HopNum>,
    ) -> StdResult<mpsc::Sender<StreamMsg>, ReactorError> {
        let mut hops = self.hops.write().expect("poisoned lock");
        let hop = hops
            .get_mut(hopnum)
            .ok_or_else(|| internal!("tried to send cell to nonexistent hop?!"))?;

        let tx = match &hop.tx {
            Some(tx) => tx.clone(),
            None => {
                // If we don't have a handle to the stream reactor,
                // it means it hasn't been spawned yet, so we have to spawn it now.
                let tx =
                    self.spawn_stream_reactor(hopnum, &hop.settings, Arc::clone(&hop.ccontrol))?;

                hop.tx = Some(tx.clone());

                // Return a copy of this sender (can't borrow because the hop
                // is behind a Mutex, and we can't keep it locked across the send()
                // await point)
                tx
            }
        };

        Ok(tx)
    }

    /// Spawn a [`StreamReactor`] for the specified hop.
    fn spawn_stream_reactor(
        &self,
        hopnum: Option<HopNum>,
        settings: &HopSettings,
        ccontrol: Arc<Mutex<CongestionControl>>,
    ) -> StdResult<mpsc::Sender<StreamMsg>, ReactorError> {
        use tor_rtcompat::SpawnExt as _;

        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        //
        // TODO(tuning): having zero buffering here is very likely suboptimal.
        // We should do *some* buffering here, and then figure out if we should it
        // up to memquota or not.
        #[allow(clippy::disallowed_methods)]
        let (fwd_stream_tx, fwd_stream_rx) = mpsc::channel(0);

        let flow_ctrl_params = Arc::new(settings.flow_ctrl_params.clone());
        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let outbound = CircHopOutbound::new(ccontrol, relay_format, flow_ctrl_params, settings);

        let stream_reactor = StreamReactor::new(
            self.runtime.clone(),
            hopnum,
            outbound,
            self.ctx.unique_id,
            fwd_stream_rx,
            self.bwd_tx.clone(),
            Arc::clone(&self.ctx.timeouts),
            #[cfg(any(feature = "hs-service", feature = "relay"))]
            Arc::clone(&self.ctx.incoming),
            self.memquota.clone(),
        );

        self.runtime
            .spawn(async {
                let _ = stream_reactor.run().await;
            })
            .map_err(|_| ReactorError::Shutdown)?;

        Ok(fwd_stream_tx)
    }
}
