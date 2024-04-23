#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// This clippy lint produces a false positive on `use strum`, below.
// Attempting to apply the lint to just the use statement fails to suppress
// this lint and instead produces another lint about a useless clippy attribute.
#![allow(clippy::single_component_path_imports)]

pub mod authority;
mod bootstrap;
pub mod config;
mod docid;
mod docmeta;
mod err;
mod event;
mod retry;
mod shared_ref;
mod state;
mod storage;

#[cfg(feature = "bridge-client")]
pub mod bridgedesc;
#[cfg(feature = "dirfilter")]
pub mod filter;

use crate::docid::{CacheUsage, ClientRequest, DocQuery};
use crate::err::BootstrapAction;
#[cfg(not(feature = "experimental-api"))]
use crate::shared_ref::SharedMutArc;
#[cfg(feature = "experimental-api")]
pub use crate::shared_ref::SharedMutArc;
use crate::storage::{DynStore, Store};
use bootstrap::AttemptId;
use event::DirProgress;
use postage::watch;
pub use retry::{DownloadSchedule, DownloadScheduleBuilder};
use scopeguard::ScopeGuard;
use tor_circmgr::CircMgr;
use tor_dirclient::SourceInfo;
use tor_error::{info_report, into_internal, warn_report};
use tor_netdir::params::NetParameters;
use tor_netdir::{DirEvent, MdReceiver, NetDir, NetDirProvider};

use async_trait::async_trait;
use futures::{stream::BoxStream, task::SpawnExt};
use tor_async_utils::oneshot;
use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};
use tor_rtcompat::Runtime;
use tracing::{debug, info, trace, warn};

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{collections::HashMap, sync::Weak};
use std::{fmt::Debug, time::SystemTime};

use crate::state::{DirState, NetDirChange};
pub use authority::{Authority, AuthorityBuilder};
pub use config::{
    DirMgrConfig, DirTolerance, DirToleranceBuilder, DownloadScheduleConfig,
    DownloadScheduleConfigBuilder, NetworkConfig, NetworkConfigBuilder,
};
pub use docid::DocId;
pub use err::Error;
pub use event::{DirBlockage, DirBootstrapEvents, DirBootstrapStatus};
pub use storage::DocumentText;
pub use tor_guardmgr::fallback::{FallbackDir, FallbackDirBuilder};
pub use tor_netdir::Timeliness;

/// Re-export of `strum` crate for use by an internal macro
use strum;

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Storage manager used by [`DirMgr`] and
/// [`BridgeDescMgr`](bridgedesc::BridgeDescMgr)
///
/// Internally, this wraps up a sqlite database.
///
/// This is a handle, which is cheap to clone; clones share state.
#[derive(Clone)]
pub struct DirMgrStore<R: Runtime> {
    /// The actual store
    pub(crate) store: Arc<Mutex<crate::DynStore>>,

    /// Be parameterized by Runtime even though we don't use it right now
    pub(crate) runtime: PhantomData<R>,
}

impl<R: Runtime> DirMgrStore<R> {
    /// Open the storage, according to the specified configuration
    pub fn new(config: &DirMgrConfig, runtime: R, offline: bool) -> Result<Self> {
        let store = Arc::new(Mutex::new(config.open_store(offline)?));
        drop(runtime);
        let runtime = PhantomData;
        Ok(DirMgrStore { store, runtime })
    }
}

/// Trait for DirMgr implementations
#[async_trait]
pub trait DirProvider: NetDirProvider {
    /// Try to change our configuration to `new_config`.
    ///
    /// Actual behavior will depend on the value of `how`.
    fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError>;

    /// Bootstrap a `DirProvider` that hasn't been bootstrapped yet.
    async fn bootstrap(&self) -> Result<()>;

    /// Return a stream of [`DirBootstrapStatus`] events to tell us about changes
    /// in the latest directory's bootstrap status.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus>;

    /// Return a [`TaskHandle`] that can be used to manage the download process.
    fn download_task_handle(&self) -> Option<TaskHandle> {
        None
    }
}

// NOTE(eta): We can't implement this for Arc<DirMgr<R>> due to trait coherence rules, so instead
//            there's a blanket impl for Arc<T> in tor-netdir.
impl<R: Runtime> NetDirProvider for DirMgr<R> {
    fn netdir(&self, timeliness: Timeliness) -> tor_netdir::Result<Arc<NetDir>> {
        use tor_netdir::Error as NetDirError;
        let netdir = self.netdir.get().ok_or(NetDirError::NoInfo)?;
        let lifetime = match timeliness {
            Timeliness::Strict => netdir.lifetime().clone(),
            Timeliness::Timely => self
                .config
                .get()
                .tolerance
                .extend_lifetime(netdir.lifetime()),
            Timeliness::Unchecked => return Ok(netdir),
        };
        let now = SystemTime::now();
        if lifetime.valid_after() > now {
            Err(NetDirError::DirNotYetValid)
        } else if lifetime.valid_until() < now {
            Err(NetDirError::DirExpired)
        } else {
            Ok(netdir)
        }
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        Box::pin(self.events.subscribe())
    }

    fn params(&self) -> Arc<dyn AsRef<tor_netdir::params::NetParameters>> {
        if let Some(netdir) = self.netdir.get() {
            // We have a directory, so we'd like to give it out for its
            // parameters.
            //
            // We do this even if the directory is expired, since parameters
            // don't really expire on any plausible timescale.
            netdir
        } else {
            // We have no directory, so we'll give out the default parameters as
            // modified by the provided override_net_params configuration.
            //
            self.default_parameters
                .lock()
                .expect("Poisoned lock")
                .clone()
        }
        // TODO(nickm): If we felt extremely clever, we could add a third case
        // where, if we have a pending directory with a validated consensus, we
        // give out that consensus's network parameters even if we _don't_ yet
        // have a full directory.  That's significant refactoring, though, for
        // an unclear amount of benefit.
    }
}

#[async_trait]
impl<R: Runtime> DirProvider for Arc<DirMgr<R>> {
    fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        DirMgr::reconfigure(self, new_config, how)
    }

    async fn bootstrap(&self) -> Result<()> {
        DirMgr::bootstrap(self).await
    }

    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus> {
        Box::pin(DirMgr::bootstrap_events(self))
    }

    fn download_task_handle(&self) -> Option<TaskHandle> {
        Some(self.task_handle.clone())
    }
}

/// A directory manager to download, fetch, and cache a Tor directory.
///
/// A DirMgr can operate in three modes:
///   * In **offline** mode, it only reads from the cache, and can
///     only read once.
///   * In **read-only** mode, it reads from the cache, but checks
///     whether it can acquire an associated lock file.  If it can, then
///     it enters read-write mode.  If not, it checks the cache
///     periodically for new information.
///   * In **read-write** mode, it knows that no other process will be
///     writing to the cache, and it takes responsibility for fetching
///     data from the network and updating the directory with new
///     directory information.
pub struct DirMgr<R: Runtime> {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: tor_config::MutCfg<DirMgrConfig>,
    /// Handle to our sqlite cache.
    // TODO(nickm): I'd like to use an rwlock, but that's not feasible, since
    // rusqlite::Connection isn't Sync.
    // TODO is needed?
    store: Arc<Mutex<DynStore>>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    // TODO(eta): Eurgh! This is so many Arcs! (especially considering this
    //            gets wrapped in an Arc)
    netdir: Arc<SharedMutArc<NetDir>>,

    /// A set of network parameters to hand out when we have no directory.
    default_parameters: Mutex<Arc<NetParameters>>,

    /// A publisher handle that we notify whenever the consensus changes.
    events: event::FlagPublisher<DirEvent>,

    /// A publisher handle that we notify whenever our bootstrapping status
    /// changes.
    send_status: Mutex<watch::Sender<event::DirBootstrapStatus>>,

    /// A receiver handle that gets notified whenever our bootstrapping status
    /// changes.
    ///
    /// We don't need to keep this drained, since `postage::watch` already knows
    /// to discard unread events.
    receive_status: DirBootstrapEvents,

    /// A circuit manager, if this DirMgr supports downloading.
    circmgr: Option<Arc<CircMgr<R>>>,

    /// Our asynchronous runtime.
    runtime: R,

    /// Whether or not we're operating in offline mode.
    offline: bool,

    /// If we're not in offline mode, stores whether or not the `DirMgr` has attempted
    /// to bootstrap yet or not.
    ///
    /// This exists in order to prevent starting two concurrent bootstrap tasks.
    ///
    /// (In offline mode, this does nothing.)
    bootstrap_started: AtomicBool,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: crate::filter::FilterConfig,

    /// A task schedule that can be used if we're bootstrapping.  If this is
    /// None, then there's currently a scheduled task in progress.
    task_schedule: Mutex<Option<TaskSchedule<R>>>,

    /// A task handle that we return to anybody who needs to manage our download process.
    task_handle: TaskHandle,
}

/// The possible origins of a document.
///
/// Used (for example) to report where we got a document from if it fails to
/// parse.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DocSource {
    /// We loaded the document from our cache.
    LocalCache,
    /// We fetched the document from a server.
    DirServer {
        /// Information about the server we fetched the document from.
        source: Option<SourceInfo>,
    },
}

impl std::fmt::Display for DocSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocSource::LocalCache => write!(f, "local cache"),
            DocSource::DirServer { source: None } => write!(f, "directory server"),
            DocSource::DirServer { source: Some(info) } => write!(f, "directory server {}", info),
        }
    }
}

impl<R: Runtime> DirMgr<R> {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async or take a runtime.
    pub async fn load_once(runtime: R, config: DirMgrConfig) -> Result<Arc<NetDir>> {
        let store = DirMgrStore::new(&config, runtime.clone(), true)?;
        let dirmgr = Arc::new(Self::from_config(config, runtime, store, None, true)?);

        // TODO: add some way to return a directory that isn't up-to-date
        let attempt = AttemptId::next();
        trace!(%attempt, "Trying to load a full directory from cache");
        let outcome = dirmgr.load_directory(attempt).await;
        trace!(%attempt, "Load result: {outcome:?}");
        let _success = outcome?;

        dirmgr
            .netdir(Timeliness::Timely)
            .map_err(|_| Error::DirectoryNotPresent)
    }

    /// Return a current netdir, either loading it or bootstrapping it
    /// as needed.
    ///
    /// Like load_once, but will try to bootstrap (or wait for another
    /// process to bootstrap) if we don't have an up-to-date
    /// bootstrapped directory.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    pub async fn load_or_bootstrap_once(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, runtime, store, circmgr).await?;
        dirmgr
            .timely_netdir()
            .map_err(|_| Error::DirectoryNotPresent)
    }

    /// Create a new `DirMgr` in online mode, but don't bootstrap it yet.
    ///
    /// The `DirMgr` can be bootstrapped later with `bootstrap`.
    pub fn create_unbootstrapped(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(DirMgr::from_config(
            config,
            runtime,
            store,
            Some(circmgr),
            false,
        )?))
    }

    /// Bootstrap a `DirMgr` created in online mode that hasn't been bootstrapped yet.
    ///
    /// This function will not return until the directory is bootstrapped enough to build circuits.
    /// It will also launch a background task that fetches any missing information, and that
    /// replaces the directory when a new one is available.
    ///
    /// This function is intended to be used together with `create_unbootstrapped`. There is no
    /// need to call this function otherwise.
    ///
    /// If bootstrapping has already successfully taken place, returns early with success.
    ///
    /// # Errors
    ///
    /// Returns an error if bootstrapping fails. If the error is [`Error::CantAdvanceState`],
    /// it may be possible to successfully bootstrap later on by calling this function again.
    ///
    /// # Panics
    ///
    /// Panics if the `DirMgr` passed to this function was not created in online mode, such as
    /// via `load_once`.
    pub async fn bootstrap(self: &Arc<Self>) -> Result<()> {
        if self.offline {
            return Err(Error::OfflineMode);
        }

        // The semantics of this are "attempt to replace a 'false' value with 'true'.
        // If the value in bootstrap_started was not 'false' when the attempt was made, returns
        // `Err`; this means another bootstrap attempt is in progress or has completed, so we
        // return early.

        // NOTE(eta): could potentially weaken the `Ordering` here in future
        if self
            .bootstrap_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!("Attempted to bootstrap twice; ignoring.");
            return Ok(());
        }

        // Use a RAII guard to reset `bootstrap_started` to `false` if we return early without
        // completing bootstrap.
        let reset_bootstrap_started = scopeguard::guard(&self.bootstrap_started, |v| {
            v.store(false, Ordering::SeqCst);
        });

        let schedule = {
            let sched = self.task_schedule.lock().expect("poisoned lock").take();
            match sched {
                Some(sched) => sched,
                None => {
                    debug!("Attempted to bootstrap twice; ignoring.");
                    return Ok(());
                }
            }
        };

        // Try to load from the cache.
        let attempt_id = AttemptId::next();
        trace!(attempt=%attempt_id, "Starting to bootstrap directory");
        let have_directory = self.load_directory(attempt_id).await?;

        let (mut sender, receiver) = if have_directory {
            info!("Loaded a good directory from cache.");
            (None, None)
        } else {
            info!("Didn't get usable directory from cache.");
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        };

        // Whether we loaded or not, we now start downloading.
        let dirmgr_weak = Arc::downgrade(self);
        self.runtime
            .spawn(async move {
                // Use an RAII guard to make sure that when this task exits, the
                // TaskSchedule object is put back.
                //
                // TODO(nick): Putting the schedule back isn't actually useful
                // if the task exits _after_ we've bootstrapped for the first
                // time, because of how bootstrap_started works.
                let mut schedule = scopeguard::guard(schedule, |schedule| {
                    if let Some(dm) = Weak::upgrade(&dirmgr_weak) {
                        *dm.task_schedule.lock().expect("poisoned lock") = Some(schedule);
                    }
                });

                // Don't warn when these are Error::ManagerDropped: that
                // means that the DirMgr has been shut down.
                if let Err(e) =
                    Self::reload_until_owner(&dirmgr_weak, &mut schedule, attempt_id, &mut sender)
                        .await
                {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn_report!(e, "Unrecovered error while waiting for bootstrap",),
                    }
                } else if let Err(e) =
                    Self::download_forever(dirmgr_weak.clone(), &mut schedule, attempt_id, sender)
                        .await
                {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn_report!(e, "Unrecovered error while downloading"),
                    }
                }
            })
            .map_err(|e| Error::from_spawn("directory updater task", e))?;

        if let Some(receiver) = receiver {
            match receiver.await {
                Ok(()) => {
                    info!("We have enough information to build circuits.");
                    // Disarm the RAII guard, since we succeeded.  Now bootstrap_started will remain true.
                    let _ = ScopeGuard::into_inner(reset_bootstrap_started);
                }
                Err(_) => {
                    warn!("Bootstrapping task exited before finishing.");
                    return Err(Error::CantAdvanceState);
                }
            }
        }
        Ok(())
    }

    /// Returns `true` if a bootstrap attempt is in progress, or successfully completed.
    pub fn bootstrap_started(&self) -> bool {
        self.bootstrap_started.load(Ordering::SeqCst)
    }

    /// Return a new directory manager from a given configuration,
    /// bootstrapping from the network as necessary.
    pub async fn bootstrap_from_config(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Self::create_unbootstrapped(config, runtime, store, circmgr)?;

        dirmgr.bootstrap().await?;

        Ok(dirmgr)
    }

    /// Try forever to either lock the storage (and thereby become the
    /// owner), or to reload the database.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    ///
    /// If we eventually become the owner, return Ok().
    async fn reload_until_owner(
        weak: &Weak<Self>,
        schedule: &mut TaskSchedule<R>,
        attempt_id: AttemptId,
        on_complete: &mut Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut logged = false;
        let mut bootstrapped;
        {
            let dirmgr = upgrade_weak_ref(weak)?;
            bootstrapped = dirmgr.netdir.get().is_some();
        }

        loop {
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                trace!("Trying to take ownership of the directory cache lock");
                if dirmgr.try_upgrade_to_readwrite()? {
                    // We now own the lock!  (Maybe we owned it before; the
                    // upgrade_to_readwrite() function is idempotent.)  We can
                    // do our own bootstrapping.
                    if logged {
                        info!("The previous owning process has given up the lock. We are now in charge of managing the directory.");
                    }
                    return Ok(());
                }
            }

            if !logged {
                logged = true;
                if bootstrapped {
                    info!("Another process is managing the directory. We'll use its cache.");
                } else {
                    info!("Another process is bootstrapping the directory. Waiting till it finishes or exits.");
                }
            }

            // We don't own the lock.  Somebody else owns the cache.  They
            // should be updating it.  Wait a bit, then try again.
            let pause = if bootstrapped {
                std::time::Duration::new(120, 0)
            } else {
                std::time::Duration::new(5, 0)
            };
            schedule.sleep(pause).await?;
            // TODO: instead of loading the whole thing we should have a
            // database entry that says when the last update was, or use
            // our state functions.
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                trace!("Trying to load from the directory cache");
                if dirmgr.load_directory(attempt_id).await? {
                    // Successfully loaded a bootstrapped directory.
                    if let Some(send_done) = on_complete.take() {
                        let _ = send_done.send(());
                    }
                    if !bootstrapped {
                        info!("The directory is now bootstrapped.");
                    }
                    bootstrapped = true;
                }
            }
        }
    }

    /// Try to fetch our directory info and keep it updated, indefinitely.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    async fn download_forever(
        weak: Weak<Self>,
        schedule: &mut TaskSchedule<R>,
        mut attempt_id: AttemptId,
        mut on_complete: Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut state: Box<dyn DirState> = {
            let dirmgr = upgrade_weak_ref(&weak)?;
            Box::new(state::GetConsensusState::new(
                dirmgr.runtime.clone(),
                dirmgr.config.get(),
                CacheUsage::CacheOkay,
                Some(dirmgr.netdir.clone()),
                #[cfg(feature = "dirfilter")]
                dirmgr
                    .filter
                    .clone()
                    .unwrap_or_else(|| Arc::new(crate::filter::NilFilter)),
            ))
        };

        trace!("Entering download loop.");

        loop {
            let mut usable = false;

            let retry_config = {
                let dirmgr = upgrade_weak_ref(&weak)?;
                // TODO(nickm): instead of getting this every time we loop, it
                // might be a good idea to refresh it with each attempt, at
                // least at the point of checking the number of attempts.
                dirmgr.config.get().schedule.retry_bootstrap
            };
            let mut retry_delay = retry_config.schedule();

            'retry_attempt: for try_num in retry_config.attempts() {
                trace!(attempt=%attempt_id, ?try_num, "Trying to download a directory.");
                let outcome = bootstrap::download(
                    Weak::clone(&weak),
                    &mut state,
                    schedule,
                    attempt_id,
                    &mut on_complete,
                )
                .await;
                trace!(attempt=%attempt_id, ?try_num, ?outcome, "Download is over.");

                if let Err(err) = outcome {
                    if state.is_ready(Readiness::Usable) {
                        usable = true;
                        info_report!(err, "Unable to completely download a directory. (Nevertheless, the directory is usable, so we'll pause for now)");
                        break 'retry_attempt;
                    }

                    match err.bootstrap_action() {
                        BootstrapAction::Nonfatal => {
                            return Err(into_internal!(
                                "Nonfatal error should not have propagated here"
                            )(err)
                            .into());
                        }
                        BootstrapAction::Reset => {}
                        BootstrapAction::Fatal => return Err(err),
                    }

                    let delay = retry_delay.next_delay(&mut rand::thread_rng());
                    warn_report!(
                        err,
                        "Unable to download a usable directory. (We will restart in {})",
                        humantime::format_duration(delay),
                    );
                    {
                        let dirmgr = upgrade_weak_ref(&weak)?;
                        dirmgr.note_reset(attempt_id);
                    }
                    schedule.sleep(delay).await?;
                    state = state.reset();
                } else {
                    info!(attempt=%attempt_id, "Directory is complete.");
                    usable = true;
                    break 'retry_attempt;
                }
            }

            if !usable {
                // we ran out of attempts.
                warn!(
                    "We failed {} times to bootstrap a directory. We're going to give up.",
                    retry_config.n_attempts()
                );
                return Err(Error::CantAdvanceState);
            } else {
                // Report success, if appropriate.
                if let Some(send_done) = on_complete.take() {
                    let _ = send_done.send(());
                }
            }

            let reset_at = state.reset_time();
            match reset_at {
                Some(t) => {
                    trace!("Sleeping until {}", time::OffsetDateTime::from(t));
                    schedule.sleep_until_wallclock(t).await?;
                }
                None => return Ok(()),
            }
            attempt_id = bootstrap::AttemptId::next();
            trace!(attempt=%attempt_id, "Beginning new attempt to bootstrap directory");
            state = state.reset();
        }
    }

    /// Get a reference to the circuit manager, if we have one.
    fn circmgr(&self) -> Result<Arc<CircMgr<R>>> {
        self.circmgr.clone().ok_or(Error::NoDownloadSupport)
    }

    /// Try to change our configuration to `new_config`.
    ///
    /// Actual behavior will depend on the value of `how`.
    pub fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        let config = self.config.get();
        // We don't support changing these: doing so basically would require us
        // to abort all our in-progress downloads, since they might be based on
        // no-longer-viable information.
        if new_config.cache_dir != config.cache_dir {
            how.cannot_change("storage.cache_dir")?;
        }
        if new_config.authorities() != config.authorities() {
            how.cannot_change("network.authorities")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        let params_changed = new_config.override_net_params != config.override_net_params;

        self.config
            .map_and_replace(|cfg| cfg.update_from_config(new_config));

        if params_changed {
            let _ignore_err = self.netdir.mutate(|netdir| {
                netdir.replace_overridden_parameters(&new_config.override_net_params);
                Ok(())
            });
            {
                let mut params = self.default_parameters.lock().expect("lock failed");
                *params = Arc::new(NetParameters::from_map(&new_config.override_net_params));
            }

            // (It's okay to ignore the error, since it just means that there
            // was no current netdir.)
            self.events.publish(DirEvent::NewConsensus);
        }

        Ok(())
    }

    /// Return a stream of [`DirBootstrapStatus`] events to tell us about changes
    /// in the latest directory's bootstrap status.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    pub fn bootstrap_events(&self) -> event::DirBootstrapEvents {
        self.receive_status.clone()
    }

    /// Replace the latest status with `progress` and broadcast to anybody
    /// watching via a [`DirBootstrapEvents`] stream.
    fn update_progress(&self, attempt_id: AttemptId, progress: DirProgress) {
        // TODO(nickm): can I kill off this lock by having something else own the sender?
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.update_progress(attempt_id, progress);
    }

    /// Update our status tracker to note that some number of errors has
    /// occurred.
    fn note_errors(&self, attempt_id: AttemptId, n_errors: usize) {
        if n_errors == 0 {
            return;
        }
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.note_errors(attempt_id, n_errors);
    }

    /// Update our status tracker to note that we've needed to reset our download attempt.
    fn note_reset(&self, attempt_id: AttemptId) {
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.note_reset(attempt_id);
    }

    /// Try to make this a directory manager with read-write access to its
    /// storage.
    ///
    /// Return true if we got the lock, or if we already had it.
    ///
    /// Return false if another process has the lock
    fn try_upgrade_to_readwrite(&self) -> Result<bool> {
        self.store
            .lock()
            .expect("Directory storage lock poisoned")
            .upgrade_to_readwrite()
    }

    /// Return a reference to the store, if it is currently read-write.
    #[cfg(test)]
    fn store_if_rw(&self) -> Option<&Mutex<DynStore>> {
        let rw = !self
            .store
            .lock()
            .expect("Directory storage lock poisoned")
            .is_readonly();
        // A race-condition is possible here, but I believe it's harmless.
        if rw {
            Some(&self.store)
        } else {
            None
        }
    }

    /// Construct a DirMgr from a DirMgrConfig.
    ///
    /// If `offline` is set, opens the SQLite store read-only and sets the offline flag in the
    /// returned manager.
    #[allow(clippy::unnecessary_wraps)] // API compat and future-proofing
    fn from_config(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Option<Arc<CircMgr<R>>>,
        offline: bool,
    ) -> Result<Self> {
        let netdir = Arc::new(SharedMutArc::new());
        let events = event::FlagPublisher::new();
        let default_parameters = NetParameters::from_map(&config.override_net_params);
        let default_parameters = Mutex::new(Arc::new(default_parameters));

        let (send_status, receive_status) = postage::watch::channel();
        let send_status = Mutex::new(send_status);
        let receive_status = DirBootstrapEvents {
            inner: receive_status,
        };
        #[cfg(feature = "dirfilter")]
        let filter = config.extensions.filter.clone();

        // We create these early so the client code can access task_handle before bootstrap() returns.
        let (task_schedule, task_handle) = TaskSchedule::new(runtime.clone());
        let task_schedule = Mutex::new(Some(task_schedule));

        Ok(DirMgr {
            config: config.into(),
            store: store.store,
            netdir,
            default_parameters,
            events,
            send_status,
            receive_status,
            circmgr,
            runtime,
            offline,
            bootstrap_started: AtomicBool::new(false),
            #[cfg(feature = "dirfilter")]
            filter,
            task_schedule,
            task_handle,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(self: &Arc<Self>, attempt_id: AttemptId) -> Result<bool> {
        let state = state::GetConsensusState::new(
            self.runtime.clone(),
            self.config.get(),
            CacheUsage::CacheOnly,
            None,
            #[cfg(feature = "dirfilter")]
            self.filter
                .clone()
                .unwrap_or_else(|| Arc::new(crate::filter::NilFilter)),
        );
        let _ = bootstrap::load(Arc::clone(self), Box::new(state), attempt_id).await?;

        Ok(self.netdir.get().is_some())
    }

    /// Return a new asynchronous stream that will receive notification
    /// whenever the consensus has changed.
    ///
    /// Multiple events may be batched up into a single item: each time
    /// this stream yields an event, all you can assume is that the event has
    /// occurred at least once.
    pub fn events(&self) -> impl futures::Stream<Item = DirEvent> {
        self.events.subscribe()
    }

    /// Try to load the text of a single document described by `doc` from
    /// storage.
    pub fn text(&self, doc: &DocId) -> Result<Option<DocumentText>> {
        use itertools::Itertools;
        let mut result = HashMap::new();
        let query: DocQuery = (*doc).into();
        let store = self.store.lock().expect("store lock poisoned");
        query.load_from_store_into(&mut result, &**store)?;
        let item = result.into_iter().at_most_one().map_err(|_| {
            Error::CacheCorruption("Found more than one entry in storage for given docid")
        })?;
        if let Some((docid, doctext)) = item {
            if &docid != doc {
                return Err(Error::CacheCorruption(
                    "Item from storage had incorrect docid.",
                ));
            }
            Ok(Some(doctext))
        } else {
            Ok(None)
        }
    }

    /// Load the text for a collection of documents.
    ///
    /// If many of the documents have the same type, this can be more
    /// efficient than calling [`text`](Self::text).
    pub fn texts<T>(&self, docs: T) -> Result<HashMap<DocId, DocumentText>>
    where
        T: IntoIterator<Item = DocId>,
    {
        let partitioned = docid::partition_by_type(docs);
        let mut result = HashMap::new();
        let store = self.store.lock().expect("store lock poisoned");
        for (_, query) in partitioned.into_iter() {
            query.load_from_store_into(&mut result, &**store)?;
        }
        Ok(result)
    }

    /// Given a request we sent and the response we got from a
    /// directory server, see whether we should expand that response
    /// into "something larger".
    ///
    /// Currently, this handles expanding consensus diffs, and nothing
    /// else.  We do it at this stage of our downloading operation
    /// because it requires access to the store.
    fn expand_response_text(&self, req: &ClientRequest, text: String) -> Result<String> {
        if let ClientRequest::Consensus(req) = req {
            if tor_consdiff::looks_like_diff(&text) {
                if let Some(old_d) = req.old_consensus_digests().next() {
                    let db_val = {
                        let s = self.store.lock().expect("Directory storage lock poisoned");
                        s.consensus_by_sha3_digest_of_signed_part(old_d)?
                    };
                    if let Some((old_consensus, meta)) = db_val {
                        info!("Applying a consensus diff");
                        let new_consensus = tor_consdiff::apply_diff(
                            old_consensus.as_str()?,
                            &text,
                            Some(*meta.sha3_256_of_signed()),
                        )?;
                        new_consensus.check_digest()?;
                        return Ok(new_consensus.to_string());
                    }
                }
                return Err(Error::Unwanted(
                    "Received a consensus diff we did not ask for",
                ));
            }
        }
        Ok(text)
    }

    /// If `state` has netdir changes to apply, apply them to our netdir.
    #[allow(clippy::cognitive_complexity)]
    fn apply_netdir_changes(
        self: &Arc<Self>,
        state: &mut Box<dyn DirState>,
        store: &mut dyn Store,
    ) -> Result<()> {
        if let Some(change) = state.get_netdir_change() {
            match change {
                NetDirChange::AttemptReplace {
                    netdir,
                    consensus_meta,
                } => {
                    // Check the new netdir is sufficient, if we have a circmgr.
                    // (Unwraps are fine because the `Option` is `Some` until we take it.)
                    if let Some(ref cm) = self.circmgr {
                        if !cm
                            .netdir_is_sufficient(netdir.as_ref().expect("AttemptReplace had None"))
                        {
                            debug!("Got a new NetDir, but it doesn't have enough guards yet.");
                            return Ok(());
                        }
                    }
                    let is_stale = {
                        // Done inside a block to not hold a long-lived copy of the NetDir.
                        self.netdir
                            .get()
                            .map(|x| {
                                x.lifetime().valid_after()
                                    > netdir
                                        .as_ref()
                                        .expect("AttemptReplace had None")
                                        .lifetime()
                                        .valid_after()
                            })
                            .unwrap_or(false)
                    };
                    if is_stale {
                        warn!("Got a new NetDir, but it's older than the one we currently have!");
                        return Err(Error::NetDirOlder);
                    }
                    let cfg = self.config.get();
                    let mut netdir = netdir.take().expect("AttemptReplace had None");
                    netdir.replace_overridden_parameters(&cfg.override_net_params);
                    self.netdir.replace(netdir);
                    self.events.publish(DirEvent::NewConsensus);
                    self.events.publish(DirEvent::NewDescriptors);

                    info!("Marked consensus usable.");
                    if !store.is_readonly() {
                        store.mark_consensus_usable(consensus_meta)?;
                        // Now that a consensus is usable, older consensuses may
                        // need to expire.
                        store.expire_all(&crate::storage::EXPIRATION_DEFAULTS)?;
                    }
                    Ok(())
                }
                NetDirChange::AddMicrodescs(mds) => {
                    self.netdir.mutate(|netdir| {
                        for md in mds.drain(..) {
                            netdir.add_microdesc(md);
                        }
                        Ok(())
                    })?;
                    self.events.publish(DirEvent::NewDescriptors);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
}

/// A degree of readiness for a given directory state object.
#[derive(Debug, Copy, Clone)]
enum Readiness {
    /// There is no more information to download.
    Complete,
    /// There is more information to download, but we don't need to
    Usable,
}

/// Try to upgrade a weak reference to a DirMgr, and give an error on
/// failure.
fn upgrade_weak_ref<T>(weak: &Weak<T>) -> Result<Arc<T>> {
    Weak::upgrade(weak).ok_or(Error::ManagerDropped)
}

/// Given a time `now`, and an amount of tolerated clock skew `tolerance`,
/// return the age of the oldest consensus that we should request at that time.
pub(crate) fn default_consensus_cutoff(
    now: SystemTime,
    tolerance: &DirTolerance,
) -> Result<SystemTime> {
    /// We _always_ allow at least this much age in our consensuses, to account
    /// for the fact that consensuses have some lifetime.
    const MIN_AGE_TO_ALLOW: Duration = Duration::from_secs(3 * 3600);
    let allow_skew = std::cmp::max(MIN_AGE_TO_ALLOW, tolerance.post_valid_tolerance);
    let cutoff = time::OffsetDateTime::from(now - allow_skew);
    // We now round cutoff to the next hour, so that we aren't leaking our exact
    // time to the directory cache.
    //
    // With the time crate, it's easier to calculate the "next hour" by rounding
    // _down_ then adding an hour; rounding up would sometimes require changing
    // the date too.
    let (h, _m, _s) = cutoff.to_hms();
    let cutoff = cutoff.replace_time(
        time::Time::from_hms(h, 0, 0)
            .map_err(tor_error::into_internal!("Failed clock calculation"))?,
    );
    let cutoff = cutoff + Duration::from_secs(3600);

    Ok(cutoff.into())
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::docmeta::{AuthCertMeta, ConsensusMeta};
    use std::time::Duration;
    use tempfile::TempDir;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_netdoc::doc::netstatus::ConsensusFlavor;
    use tor_netdoc::doc::{authcert::AuthCertKeyIds, netstatus::Lifetime};
    use tor_rtcompat::SleepProvider;

    pub(crate) fn new_mgr<R: Runtime>(runtime: R) -> (TempDir, DirMgr<R>) {
        let dir = TempDir::new().unwrap();
        let config = DirMgrConfig {
            cache_dir: dir.path().into(),
            ..Default::default()
        };
        let store = DirMgrStore::new(&config, runtime.clone(), false).unwrap();
        let dirmgr = DirMgr::from_config(config, runtime, store, None, false).unwrap();

        (dir, dirmgr)
    }

    #[test]
    fn failing_accessors() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let (_tempdir, mgr) = new_mgr(rt);

            assert!(mgr.circmgr().is_err());
            assert!(mgr.netdir(Timeliness::Unchecked).is_err());
        });
    }

    #[test]
    fn load_and_store_internals() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

            let (_tempdir, mgr) = new_mgr(rt);

            // Seed the storage with a bunch of junk.
            let d1 = [5_u8; 32];
            let d2 = [7; 32];
            let d3 = [42; 32];
            let d4 = [99; 20];
            let d5 = [12; 20];
            let certid1 = AuthCertKeyIds {
                id_fingerprint: d4.into(),
                sk_fingerprint: d5.into(),
            };
            let certid2 = AuthCertKeyIds {
                id_fingerprint: d5.into(),
                sk_fingerprint: d4.into(),
            };

            {
                let mut store = mgr.store.lock().unwrap();

                store
                    .store_microdescs(
                        &[
                            ("Fake micro 1", &d1),
                            ("Fake micro 2", &d2),
                            ("Fake micro 3", &d3),
                        ],
                        now,
                    )
                    .unwrap();

                #[cfg(feature = "routerdesc")]
                store
                    .store_routerdescs(&[("Fake rd1", now, &d4), ("Fake rd2", now, &d5)])
                    .unwrap();

                store
                    .store_authcerts(&[
                        (
                            AuthCertMeta::new(certid1, now, tomorrow),
                            "Fake certificate one",
                        ),
                        (
                            AuthCertMeta::new(certid2, now, tomorrow),
                            "Fake certificate two",
                        ),
                    ])
                    .unwrap();

                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, tomorrow, later).unwrap(),
                    [102; 32],
                    [103; 32],
                );
                store
                    .store_consensus(&cmeta, ConsensusFlavor::Microdesc, false, "Fake consensus!")
                    .unwrap();
            }

            // Try to get it with text().
            let t1 = mgr.text(&DocId::Microdesc(d1)).unwrap().unwrap();
            assert_eq!(t1.as_str(), Ok("Fake micro 1"));

            let t2 = mgr
                .text(&DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    cache_usage: CacheUsage::CacheOkay,
                })
                .unwrap()
                .unwrap();
            assert_eq!(t2.as_str(), Ok("Fake consensus!"));

            let t3 = mgr.text(&DocId::Microdesc([255; 32])).unwrap();
            assert!(t3.is_none());

            // Now try texts()
            let d_bogus = DocId::Microdesc([255; 32]);
            let res = mgr
                .texts(vec![
                    DocId::Microdesc(d2),
                    DocId::Microdesc(d3),
                    d_bogus,
                    DocId::AuthCert(certid2),
                    #[cfg(feature = "routerdesc")]
                    DocId::RouterDesc(d5),
                ])
                .unwrap();
            assert_eq!(
                res.get(&DocId::Microdesc(d2)).unwrap().as_str(),
                Ok("Fake micro 2")
            );
            assert_eq!(
                res.get(&DocId::Microdesc(d3)).unwrap().as_str(),
                Ok("Fake micro 3")
            );
            assert!(!res.contains_key(&d_bogus));
            assert_eq!(
                res.get(&DocId::AuthCert(certid2)).unwrap().as_str(),
                Ok("Fake certificate two")
            );
            #[cfg(feature = "routerdesc")]
            assert_eq!(
                res.get(&DocId::RouterDesc(d5)).unwrap().as_str(),
                Ok("Fake rd2")
            );
        });
    }

    #[test]
    fn make_consensus_request() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

            let (_tempdir, mgr) = new_mgr(rt);
            let config = DirMgrConfig::default();

            // Try with an empty store.
            let req = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_consensus_request(
                    now,
                    ConsensusFlavor::Microdesc,
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let tolerance = DirTolerance::default().post_valid_tolerance;
            match req {
                ClientRequest::Consensus(r) => {
                    assert_eq!(r.old_consensus_digests().count(), 0);
                    let date = r.last_consensus_date().unwrap();
                    assert!(date >= now - tolerance);
                    assert!(date <= now - tolerance + Duration::from_secs(3600));
                }
                _ => panic!("Wrong request type"),
            }

            // Add a fake consensus record.
            let d_prev = [42; 32];
            {
                let mut store = mgr.store.lock().unwrap();

                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, tomorrow, later).unwrap(),
                    d_prev,
                    [103; 32],
                );
                store
                    .store_consensus(&cmeta, ConsensusFlavor::Microdesc, false, "Fake consensus!")
                    .unwrap();
            }

            // Now try again.
            let req = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_consensus_request(
                    now,
                    ConsensusFlavor::Microdesc,
                    &**store,
                    &config,
                )
                .unwrap()
            };
            match req {
                ClientRequest::Consensus(r) => {
                    let ds: Vec<_> = r.old_consensus_digests().collect();
                    assert_eq!(ds.len(), 1);
                    assert_eq!(ds[0], &d_prev);
                    assert_eq!(r.last_consensus_date(), Some(now));
                }
                _ => panic!("Wrong request type"),
            }
        });
    }

    #[test]
    fn make_other_requests() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            use rand::Rng;
            let (_tempdir, mgr) = new_mgr(rt);

            let certid1 = AuthCertKeyIds {
                id_fingerprint: [99; 20].into(),
                sk_fingerprint: [100; 20].into(),
            };
            let mut rng = testing_rng();
            #[cfg(feature = "routerdesc")]
            let rd_ids: Vec<DocId> = (0..1000).map(|_| DocId::RouterDesc(rng.gen())).collect();
            let md_ids: Vec<DocId> = (0..1000).map(|_| DocId::Microdesc(rng.gen())).collect();
            let config = DirMgrConfig::default();

            // Try an authcert.
            let query = DocId::AuthCert(certid1);
            let store = mgr.store.lock().unwrap();
            let reqs =
                bootstrap::make_requests_for_documents(&mgr.runtime, &[query], &**store, &config)
                    .unwrap();
            assert_eq!(reqs.len(), 1);
            let req = &reqs[0];
            if let ClientRequest::AuthCert(r) = req {
                assert_eq!(r.keys().next(), Some(&certid1));
            } else {
                panic!();
            }

            // Try a bunch of mds.
            let reqs =
                bootstrap::make_requests_for_documents(&mgr.runtime, &md_ids, &**store, &config)
                    .unwrap();
            assert_eq!(reqs.len(), 2);
            assert!(matches!(reqs[0], ClientRequest::Microdescs(_)));

            // Try a bunch of rds.
            #[cfg(feature = "routerdesc")]
            {
                let reqs = bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &rd_ids,
                    &**store,
                    &config,
                )
                .unwrap();
                assert_eq!(reqs.len(), 2);
                assert!(matches!(reqs[0], ClientRequest::RouterDescs(_)));
            }
        });
    }

    #[test]
    fn expand_response() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let day = Duration::from_secs(86400);
            let config = DirMgrConfig::default();

            let (_tempdir, mgr) = new_mgr(rt);

            // Try a simple request: nothing should happen.
            let q = DocId::Microdesc([99; 32]);
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(&mgr.runtime, &[q], &**store, &config)
                    .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "ABC".to_string());
            assert_eq!(&expanded.unwrap(), "ABC");

            // Try a consensus response that doesn't look like a diff in
            // response to a query that doesn't ask for one.
            let latest_id = DocId::LatestConsensus {
                flavor: ConsensusFlavor::Microdesc,
                cache_usage: CacheUsage::CacheOkay,
            };
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &[latest_id],
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "DEF".to_string());
            assert_eq!(&expanded.unwrap(), "DEF");

            // Now stick some metadata and a string into the storage so that
            // we can ask for a diff.
            {
                let mut store = mgr.store.lock().unwrap();
                let d_in = [0x99; 32]; // This one, we can fake.
                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, now + day, now + 2 * day).unwrap(),
                    d_in,
                    d_in,
                );
                store
                    .store_consensus(
                        &cmeta,
                        ConsensusFlavor::Microdesc,
                        false,
                        "line 1\nline2\nline 3\n",
                    )
                    .unwrap();
            }

            // Try expanding something that isn't a consensus, even if we'd like
            // one.
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &[latest_id],
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "hello".to_string());
            assert_eq!(&expanded.unwrap(), "hello");

            // Finally, try "expanding" a diff (by applying it and checking the digest.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 8382374ca766873eb0d2530643191c6eaa2c5e04afa554cbac349b5d0592d300
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(&r[0], diff);

            assert_eq!(expanded.unwrap(), "line 1\nreplacement line\nline 3\n");

            // If the digest is wrong, that should get rejected.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 9999999999999999999999999999999999999999999999999999999999999999
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(&r[0], diff);
            assert!(expanded.is_err());
        });
    }
}
