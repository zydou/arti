//! Types for building circuits, or otherwise acting as a "client".

use std::sync::Arc;

use anyhow::Context;
use tor_chanmgr::ChanMgr;
use tor_circmgr::{CircMgr, CircMgrConfig};
use tor_dirmgr::{DirMgr, DirMgrConfig, DirMgrStore, DirProvider};
use tor_guardmgr::{GuardMgr, GuardMgrConfig};
use tor_persist::FsStateMgr;
use tor_rtcompat::Runtime;
use tor_rtcompat::scheduler::TaskHandle;

/// A "client" used by relays to construct circuits. For example a relay needs to build
/// bandwidth-testing circuits, reachability-testing circuits, and possibly in the future anonymous
/// circuits.
///
/// The idea here is that this [`RelayClient`] will encapsulate everything needed for building
/// circuits. So the relay itself doesn't need to worry about a channel manager, guard manager, etc.
/// Instead we provide methods here for building whatever circuits the relay may need, and with
/// whatever properties the relay needs.
pub(crate) struct RelayClient<R: Runtime> {
    /// The provided runtime.
    runtime: R,

    /// The provided state manager.
    state_mgr: FsStateMgr,

    /// Channel manager, used by circuits etc.
    #[expect(unused)] // TODO RELAY remove
    chanmgr: Arc<ChanMgr<R>>,

    /// Guard manager.
    #[expect(unused)] // TODO RELAY remove
    guardmgr: GuardMgr<R>,

    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<CircMgr<R>>,

    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<dyn DirProvider>,
}

impl<R: Runtime> RelayClient<R> {
    /// Create a new [`RelayClient`].
    ///
    /// You must call [`RelayClient::launch_background_tasks()`] before using.
    pub(crate) fn new(
        runtime: R,
        chanmgr: Arc<ChanMgr<R>>,
        guardmgr_config: &impl GuardMgrConfig,
        circmgr_config: &impl CircMgrConfig,
        dirmgr_config: DirMgrConfig,
        state_mgr: FsStateMgr,
    ) -> anyhow::Result<Self> {
        // TODO: We probably don't want a guard manager for relays,
        // unless we plan to build anonymous circuits.
        // See https://gitlab.torproject.org/tpo/core/arti/-/issues/1737.
        // If we do want a guard manager and anonymous circuits,
        // we should think more about whether our anonymous circuits can be differentiated from
        // other circuits, and make sure that we're not closing channels for "client reasons" as
        // these channels will also be used by the relay for relaying Tor user traffic.
        // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3552#note_3313591.
        let guardmgr = GuardMgr::new(runtime.clone(), state_mgr.clone(), guardmgr_config)
            .context("Failed to initialize the guard manager")?;

        // TODO: We might not want a circuit manager for relays,
        // but we will probably want its path construction logic.
        // We need to be able to build circuits for reachability testing and bandwidth measurement.
        let circmgr = Arc::new(
            CircMgr::new(
                circmgr_config,
                state_mgr.clone(),
                &runtime,
                Arc::clone(&chanmgr),
                &guardmgr,
            )
            .context("Failed to initialize the circuit manager")?,
        );

        let dirmgr_store =
            DirMgrStore::new(&dirmgr_config, runtime.clone(), /* offline= */ false)
                .context("Failed to initialize directory store")?;

        // TODO: We want to use tor-dirserver as a `NetDirProvider` in the future if possible to
        // avoid having two document downloaders, and so that we can download documents over direct
        // TCP connections rather than over circuits.
        let dirmgr = Arc::new(
            DirMgr::create_unbootstrapped(
                dirmgr_config,
                runtime.clone(),
                dirmgr_store,
                Arc::clone(&circmgr),
            )
            .context("Failed to initialize the directory manager")?,
        );

        Ok(Self {
            runtime,
            state_mgr,
            chanmgr,
            guardmgr,
            circmgr,
            dirmgr,
        })
    }

    /// Launch background tasks for any of the client's submodules.
    ///
    /// The background tasks will stop when the returned [`TaskHandle`]s are dropped.
    pub(crate) fn launch_background_tasks(&self) -> anyhow::Result<Vec<TaskHandle>> {
        self.circmgr
            .launch_background_tasks(&self.runtime, &self.dirmgr, self.state_mgr.clone())
            .context("Failed to launch circuit manager background tasks")
    }

    /// Bootstrap this client by ensuring we have directory documents downloaded.
    ///
    /// TODO: We want to use tor-dirserver as a `NetDirProvider` in the future, so hopefully we won't
    /// need this `bootstrap()` method as directory downloads will be performed elsewhere.
    pub(crate) async fn bootstrap(&self) -> anyhow::Result<()> {
        self.dirmgr
            .bootstrap()
            .await
            .context("Failed to bootstrap the directory manager")?;

        Ok(())
    }
}
