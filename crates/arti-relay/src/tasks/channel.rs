//! Channel tasks of the arti-relay.
//!
//! The tasks are:
//!     * [`ChannelHouseKeepingTask`] which is in charge of regularly going over existing channels
//!       to clean up expiring ones and prune duplicates. At the start, it will run in
//!       [`ChannelHouseKeepingTask::START_TICK_TIME`] seconds and then the channel expiry function
//!       tells it how much time to sleep.
//!     * [`update_create_request_handler_netparams`] which is in charge of updating the
//!       circuit-related network parameters of the [`CreateRequestHandler`], which is shared with
//!       the [`ChanMgr`].

use anyhow::Context;
use futures::StreamExt as _;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
use tracing::debug;

use tor_chanmgr::ChanMgr;
use tor_error::{into_internal, warn_report};
use tor_netdir::params::NetParameters;
use tor_netdir::{DirEvent, NetDirProvider};
use tor_proto::ccparams::{
    CongestionWindowParamsBuilder, FixedWindowParamsBuilder, RoundTripEstimatorParamsBuilder,
    VegasParamsBuilder,
};
use tor_proto::relay::{CircNetParameters, CongestionControlNetParams, CreateRequestHandler};
use tor_proto::{CellCount, FlowCtrlParameters};
use tor_rtcompat::Runtime;
use tor_units::Percentage;

/// Channel housekeeping standalone background task.
pub(crate) struct ChannelHouseKeepingTask<R: Runtime> {
    /// Weak reference to the ChanMgr. If it disappears, task stops.
    mgr: Weak<ChanMgr<R>>,
}

impl<R: Runtime> ChannelHouseKeepingTask<R> {
    /// Starting tick time is to run in 3 minutes. The ChanMgr expire channels uses a default of
    /// 180 seconds and so we simply align with that for the first run. After that, the channel
    /// subsystems will tell us how long to wait if any channels.
    const START_TICK_TIME: Duration = Duration::from_secs(180);

    /// Constructor.
    pub(crate) fn new(mgr: &Arc<ChanMgr<R>>) -> Self {
        Self {
            mgr: Arc::downgrade(mgr),
        }
    }

    /// Run the background task.
    #[allow(clippy::unused_async)] // TODO(relay)
    async fn run(&mut self) -> anyhow::Result<Duration> {
        let mgr = Weak::upgrade(&self.mgr).context("Channel manager is gone")?;
        // Expire any channels that are possibly closing.
        let next_expiry = mgr.expire_channels();

        // TODO: Another action is to prune duplicate channels like C-tor does in
        // channel_update_bad_for_new_circs().
        Ok(next_expiry)
    }

    /// Start the task.
    pub(crate) async fn start(&mut self) -> anyhow::Result<void::Void> {
        let mut next_tick_in = Self::START_TICK_TIME;
        debug!("Channel housekeeping task starting.");
        loop {
            // Sleep until next tick.
            tokio::time::sleep(next_tick_in).await;
            // Run this task. The returned value is the next tick.
            next_tick_in = self
                .run()
                .await
                .context("Shutting down channel housekeeping task")?;
        }
    }
}

/// A task which waits for new consensus documents and updates the parameters
/// for a [`CreateRequestHandler`].
pub(crate) async fn update_create_request_handler_netparams(
    create_request_handler: Arc<CreateRequestHandler>,
    netdir: Arc<dyn NetDirProvider>,
) -> anyhow::Result<void::Void> {
    /// A helper to call [`build_circ_net_params()`] and log errors.
    fn build_helper(params: &NetParameters) -> Option<CircNetParameters> {
        match build_circ_net_params(params) {
            Ok(params) => Some(params),
            Err(e) => {
                // This is weird, but probably not worth shutting down the relay for.
                // Let's ignore this and hope that a future consensus is better.
                warn_report!(e, "Could not build circuit params for latest consensus");
                None
            }
        }
    }

    let mut consensus_events = netdir
        .events()
        .filter(|ev| std::future::ready(matches!(ev, DirEvent::NewConsensus)));

    // We do this after subscribing with `events()` above
    // so that we don't miss any changes.
    // https://gitlab.torproject.org/tpo/core/arti/-/issues/2420
    if let Some(params) = build_helper(netdir.params().as_ref().as_ref()) {
        create_request_handler.update_params(params);
    }

    // Loop forever waiting for consensus updates.
    loop {
        let _event = consensus_events
            .next()
            .await
            .context("netdir consensus event stream ended unexpectedly")?;

        let Some(params) = build_helper(netdir.params().as_ref().as_ref()) else {
            continue;
        };

        // Update the handler with the latest parameters.
        create_request_handler.update_params(params);
    }
}

/// Build a [`CircNetParameters`] from a [`NetParameters`].
///
/// This should just copy values from the network status into a `CircNetParameters`,
/// which is how a [`CreateRequestHandler`] accepts network parameters for building circuits.
// TODO: This shares a bunch of code with `exit_circparams_from_netparams()`.
// It would be nice if we could simplify/dedup this somehow.
pub(crate) fn build_circ_net_params(params: &NetParameters) -> anyhow::Result<CircNetParameters> {
    // TODO(arti#2442): The builder pattern throughout seems like a footgun.

    let vegas_exit_params = (
        params.cc_vegas_alpha_exit.into(),
        params.cc_vegas_beta_exit.into(),
        params.cc_vegas_delta_exit.into(),
        params.cc_vegas_gamma_exit.into(),
        params.cc_vegas_sscap_exit.into(),
    );

    let vegas_exit = VegasParamsBuilder::default()
        .cell_in_queue_params(vegas_exit_params.into())
        .ss_cwnd_max(params.cc_ss_max.into())
        .cwnd_full_gap(params.cc_cwnd_full_gap.into())
        .cwnd_full_min_pct(Percentage::new(
            params.cc_cwnd_full_minpct.as_percent().get() as u32,
        ))
        .cwnd_full_per_cwnd(params.cc_cwnd_full_per_cwnd.into())
        .build()
        .map_err(into_internal!("Unable to build VegasParams"))?;

    let fixed_window = FixedWindowParamsBuilder::default()
        .circ_window_start(params.circuit_window.get() as u16)
        .circ_window_min(params.circuit_window.lower() as u16)
        .circ_window_max(params.circuit_window.upper() as u16)
        .build()
        .map_err(into_internal!("Unable to build FixedWindowParams"))?;

    let cwnd = CongestionWindowParamsBuilder::default()
        .cwnd_init(params.cc_cwnd_init.into())
        .cwnd_inc_pct_ss(Percentage::new(
            params.cc_cwnd_inc_pct_ss.as_percent().get() as u32,
        ))
        .cwnd_inc(params.cc_cwnd_inc.into())
        .cwnd_inc_rate(params.cc_cwnd_inc_rate.into())
        .cwnd_min(params.cc_cwnd_min.into())
        .cwnd_max(params.cc_cwnd_max.into())
        .sendme_inc(params.cc_sendme_inc.into())
        .build()
        .map_err(into_internal!("Unable to build CongestionWindowParams"))?;

    let rtt = RoundTripEstimatorParamsBuilder::default()
        .ewma_cwnd_pct(Percentage::new(
            params.cc_ewma_cwnd_pct.as_percent().get() as u32
        ))
        .ewma_max(params.cc_ewma_max.into())
        .ewma_ss_max(params.cc_ewma_ss.into())
        .rtt_reset_pct(Percentage::new(
            params.cc_rtt_reset_pct.as_percent().get() as u32
        ))
        .build()
        .map_err(into_internal!("Unable to build RoundTripEstimatorParams"))?;

    let flow_ctrl = FlowCtrlParameters {
        cc_xoff_client: CellCount::new(params.cc_xoff_client.get_u32()),
        cc_xoff_exit: CellCount::new(params.cc_xoff_exit.get_u32()),
        cc_xon_rate: CellCount::new(params.cc_xon_rate.get_u32()),
        cc_xon_change_pct: params.cc_xon_change_pct.get_u32(),
        cc_xon_ewma_cnt: params.cc_xon_ewma_cnt.get_u32(),
    };

    let cc = CongestionControlNetParams {
        fixed_window,
        vegas_exit,
        cwnd,
        rtt,
        flow_ctrl,
    };

    Ok(CircNetParameters {
        extend_by_ed25519_id: params.extend_by_ed25519_id.into(),
        cc,
    })
}
