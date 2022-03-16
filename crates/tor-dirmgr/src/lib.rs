//! `tor-dirmgr`: Code to fetch, store, and update Tor directory information.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.
//!
//! # Compile-time features
//!
//! `mmap` (default) -- Use memory mapping to reduce the memory load for
//! reading large directory objects from disk.
//!
//! `static` -- Try to link with a static copy of sqlite3.
//!
//! `routerdesc` -- (Incomplete) support for downloading and storing
//!      router descriptors.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

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

use crate::docid::{CacheUsage, ClientRequest, DocQuery};
#[cfg(not(feature = "experimental-api"))]
use crate::shared_ref::SharedMutArc;
#[cfg(feature = "experimental-api")]
pub use crate::shared_ref::SharedMutArc;
use crate::storage::DynStore;
use postage::watch;
pub use retry::DownloadSchedule;
use tor_circmgr::CircMgr;
use tor_netdir::NetDir;
use tor_netdoc::doc::netstatus::ConsensusFlavor;

use async_trait::async_trait;
use futures::{channel::oneshot, stream::BoxStream, task::SpawnExt};
use tor_rtcompat::{Runtime, SleepProviderExt};
use tracing::{debug, info, trace, warn};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{collections::HashMap, sync::Weak};
use std::{fmt::Debug, time::SystemTime};

pub use authority::{Authority, AuthorityBuilder};
pub use config::{
    DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig, DownloadScheduleConfigBuilder,
    NetworkConfig, NetworkConfigBuilder,
};
pub use docid::DocId;
pub use err::Error;
pub use event::{DirBootstrapEvents, DirBootstrapStatus, DirEvent, DirStatus};
pub use storage::DocumentText;
pub use tor_netdir::fallback::{FallbackDir, FallbackDirBuilder};

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for DirMgr implementations
#[async_trait]
pub trait DirProvider {
    /// Return a handle to our latest directory, if we have one.
    fn latest_netdir(&self) -> Option<Arc<NetDir>>;

    /// Return a new asynchronous stream that will receive notification
    /// whenever the consensus has changed.
    ///
    /// Multiple events may be batched up into a single item: each time
    /// this stream yields an event, all you can assume is that the event has
    /// occurred at least once.
    fn events(&self) -> BoxStream<'static, DirEvent>;

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
}

#[async_trait]
impl<R: Runtime> DirProvider for Arc<DirMgr<R>> {
    fn latest_netdir(&self) -> Option<Arc<NetDir>> {
        self.opt_netdir()
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        Box::pin(self.events.subscribe())
    }

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
    store: Mutex<DynStore>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: SharedMutArc<NetDir>,

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
}

/// RAII guard to reset an AtomicBool on drop.
struct BoolResetter<'a> {
    /// The bool to reset.
    inner: &'a AtomicBool,
    /// What value to store.
    reset_to: bool,
    /// What atomic ordering to use.
    ordering: Ordering,
}

impl<'a> Drop for BoolResetter<'a> {
    fn drop(&mut self) {
        self.inner.store(self.reset_to, self.ordering);
    }
}

impl<'a> BoolResetter<'a> {
    /// Disarm the guard, consuming it to make it not reset any more.
    fn disarm(self) {
        std::mem::forget(self);
    }
}

/// The possible origins of a document.
///
/// Used (for example) to report where we got a document from if it fails to
/// parse.
#[derive(Debug, Clone, derive_more::Display)]
#[non_exhaustive]
pub enum DocSource {
    /// We loaded the document from our cache.
    #[display(fmt = "local cache")]
    LocalCache,
    /// We fetched the document from a server.
    //
    // TODO: we'll should add a lot more information here in the future, once
    // it's available from tor_dirclient::DirSource,
    #[display(fmt = "directory server")]
    DirServer {},
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
        let dirmgr = Arc::new(Self::from_config(config, runtime, None, true)?);

        // TODO: add some way to return a directory that isn't up-to-date
        let _success = dirmgr.load_directory().await?;

        dirmgr.opt_netdir().ok_or(Error::DirectoryNotPresent)
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
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, runtime, circmgr).await?;
        dirmgr.netdir()
    }

    /// Create a new `DirMgr` in online mode, but don't bootstrap it yet.
    ///
    /// The `DirMgr` can be bootstrapped later with `bootstrap`.
    pub fn create_unbootstrapped(
        config: DirMgrConfig,
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(DirMgr::from_config(
            config,
            runtime,
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
        let resetter = BoolResetter {
            inner: &self.bootstrap_started,
            reset_to: false,
            ordering: Ordering::SeqCst,
        };

        // Try to load from the cache.
        let have_directory = self.load_directory().await?;

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
                // NOTE: This is a daemon task.  It should eventually get
                // treated as one.

                // Don't warn when these are Error::ManagerDropped: that
                // means that the DirMgr has been shut down.
                if let Err(e) = Self::reload_until_owner(&dirmgr_weak, &mut sender).await {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn!("Unrecovered error while waiting for bootstrap: {}", e),
                    }
                } else if let Err(e) = Self::download_forever(dirmgr_weak, sender).await {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn!("Unrecovered error while downloading: {}", e),
                    }
                }
            })
            .map_err(|e| Error::from_spawn("directory updater task", e))?;

        if let Some(receiver) = receiver {
            match receiver.await {
                Ok(()) => {
                    info!("We have enough information to build circuits.");
                    // Disarm the RAII guard, since we succeeded.
                    resetter.disarm();
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
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Self::create_unbootstrapped(config, runtime, circmgr)?;

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
        on_complete: &mut Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut logged = false;
        let mut bootstrapped;
        let runtime;
        {
            let dirmgr = upgrade_weak_ref(weak)?;
            runtime = dirmgr.runtime.clone();
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
            runtime.sleep(pause).await;
            // TODO: instead of loading the whole thing we should have a
            // database entry that says when the last update was, or use
            // our state functions.
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                trace!("Trying to load from the directory cache");
                if dirmgr.load_directory().await? {
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
        mut on_complete: Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut state: Box<dyn DirState> = Box::new(state::GetConsensusState::new(
            Weak::clone(&weak),
            CacheUsage::CacheOkay,
        )?);

        let runtime = {
            let dirmgr = upgrade_weak_ref(&weak)?;
            dirmgr.runtime.clone()
        };

        loop {
            let mut usable = false;

            let retry_config = {
                let dirmgr = upgrade_weak_ref(&weak)?;
                // TODO(nickm): instead of getting this every time we loop, it
                // might be a good idea to refresh it with each attempt, at
                // least at the point of checking the number of attempts.
                *dirmgr.config.get().schedule().retry_bootstrap()
            };
            let mut retry_delay = retry_config.schedule();

            'retry_attempt: for _ in retry_config.attempts() {
                let (newstate, recoverable_err) =
                    bootstrap::download(Weak::clone(&weak), state, &mut on_complete).await?;
                state = newstate;

                if let Some(err) = recoverable_err {
                    if state.is_ready(Readiness::Usable) {
                        usable = true;
                        info!("Unable to completely download a directory: {}.  Nevertheless, the directory is usable, so we'll pause for now.", err);
                        break 'retry_attempt;
                    }

                    let delay = retry_delay.next_delay(&mut rand::thread_rng());
                    warn!(
                        "Unable to download a usable directory: {}.  We will restart in {:?}.",
                        err, delay
                    );
                    runtime.sleep(delay).await;
                    state = state.reset()?;
                } else {
                    info!("Directory is complete.");
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
                Some(t) => runtime.sleep_until_wallclock(t).await,
                None => return Ok(()),
            }
            state = state.reset()?;
        }
    }

    /// Get a reference to the circuit manager, if we have one.
    fn circmgr(&self) -> Result<Arc<CircMgr<R>>> {
        self.circmgr
            .as_ref()
            .map(Arc::clone)
            .ok_or(Error::NoDownloadSupport)
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
        if new_config.cache_path() != config.cache_path() {
            how.cannot_change("storage.cache_path")?;
        }
        if new_config.authorities() != config.authorities() {
            how.cannot_change("network.authorities")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        let params_changed = new_config.override_net_params() != config.override_net_params();

        self.config
            .map_and_replace(|cfg| cfg.update_from_config(new_config));

        if params_changed {
            let _ignore_err = self.netdir.mutate(|netdir| {
                netdir.replace_overridden_parameters(new_config.override_net_params());
                Ok(())
            });
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

    /// Replace the latest status with `new_status` and broadcast to anybody
    /// watching via a [`DirBootstrapEvents`] stream.
    fn update_status(&self, new_status: DirStatus) {
        // TODO(nickm): can I kill off this lock by having something else own the sender?
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.update(new_status);
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
    fn from_config(
        config: DirMgrConfig,
        runtime: R,
        circmgr: Option<Arc<CircMgr<R>>>,
        offline: bool,
    ) -> Result<Self> {
        let store = Mutex::new(config.open_store(offline)?);
        let netdir = SharedMutArc::new();
        let events = event::FlagPublisher::new();

        let (send_status, receive_status) = postage::watch::channel();
        let send_status = Mutex::new(send_status);
        let receive_status = DirBootstrapEvents {
            inner: receive_status,
        };

        Ok(DirMgr {
            config: config.into(),
            store,
            netdir,
            events,
            send_status,
            receive_status,
            circmgr,
            runtime,
            offline,
            bootstrap_started: AtomicBool::new(false),
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(self: &Arc<Self>) -> Result<bool> {
        let state = state::GetConsensusState::new(Arc::downgrade(self), CacheUsage::CacheOnly)?;
        let _ = bootstrap::load(Arc::clone(self), Box::new(state)).await?;

        Ok(self.netdir.get().is_some())
    }

    /// Return an Arc handle to our latest directory, if we have one.
    pub fn opt_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.get()
    }

    /// Return an Arc handle to our latest directory, returning an error if there is none.
    ///
    /// # Errors
    ///
    /// Errors with [`Error::DirectoryNotPresent`] if the `DirMgr` hasn't been bootstrapped yet.
    // TODO: Add variants of this that make sure that it's up-to-date?
    pub fn netdir(&self) -> Result<Arc<NetDir>> {
        self.opt_netdir().ok_or(Error::DirectoryNotPresent)
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
        let query = (*doc).into();
        self.load_documents_into(&query, &mut result)?;
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
        for (_, query) in partitioned.into_iter() {
            self.load_documents_into(&query, &mut result)?;
        }
        Ok(result)
    }

    /// Load all the documents for a single DocumentQuery from the store.
    fn load_documents_into(
        &self,
        query: &DocQuery,
        result: &mut HashMap<DocId, DocumentText>,
    ) -> Result<()> {
        use DocQuery::*;
        let store = self.store.lock().expect("Directory storage lock poisoned");
        match query {
            LatestConsensus {
                flavor,
                cache_usage,
            } => {
                if *cache_usage == CacheUsage::MustDownload {
                    // Do nothing: we don't want a cached consensus.
                    trace!("MustDownload is set; not checking for cached consensus.");
                } else if let Some(c) =
                    store.latest_consensus(*flavor, cache_usage.pending_requirement())?
                {
                    trace!("Found a reasonable consensus in the cache");
                    let id = DocId::LatestConsensus {
                        flavor: *flavor,
                        cache_usage: *cache_usage,
                    };
                    result.insert(id, c.into());
                }
            }
            AuthCert(ids) => result.extend(
                store
                    .authcerts(ids)?
                    .into_iter()
                    .map(|(id, c)| (DocId::AuthCert(id), DocumentText::from_string(c))),
            ),
            Microdesc(digests) => {
                result.extend(
                    store
                        .microdescs(digests)?
                        .into_iter()
                        .map(|(id, md)| (DocId::Microdesc(id), DocumentText::from_string(md))),
                );
            }
            #[cfg(feature = "routerdesc")]
            RouterDesc(digests) => result.extend(
                store
                    .routerdescs(digests)?
                    .into_iter()
                    .map(|(id, rd)| (DocId::RouterDesc(id), DocumentText::from_string(rd))),
            ),
        }
        Ok(())
    }

    /// Convert a DocQuery into a set of ClientRequests, suitable for sending
    /// to a directory cache.
    ///
    /// This conversion has to be a function of the dirmgr, since it may
    /// require knowledge about our current state.
    fn query_into_requests(&self, q: DocQuery) -> Result<Vec<ClientRequest>> {
        let mut res = Vec::new();
        for q in q.split_for_download() {
            match q {
                DocQuery::LatestConsensus { flavor, .. } => {
                    res.push(self.make_consensus_request(self.runtime.wallclock(), flavor)?);
                }
                DocQuery::AuthCert(ids) => {
                    res.push(ClientRequest::AuthCert(ids.into_iter().collect()));
                }
                DocQuery::Microdesc(ids) => {
                    res.push(ClientRequest::Microdescs(ids.into_iter().collect()));
                }
                #[cfg(feature = "routerdesc")]
                DocQuery::RouterDesc(ids) => {
                    res.push(ClientRequest::RouterDescs(ids.into_iter().collect()));
                }
            }
        }
        Ok(res)
    }

    /// Construct an appropriate ClientRequest to download a consensus
    /// of the given flavor.
    fn make_consensus_request(
        &self,
        now: SystemTime,
        flavor: ConsensusFlavor,
    ) -> Result<ClientRequest> {
        let mut request = tor_dirclient::request::ConsensusRequest::new(flavor);

        let default_cutoff = default_consensus_cutoff(now)?;

        let r = self.store.lock().expect("Directory storage lock poisoned");
        match r.latest_consensus_meta(flavor) {
            Ok(Some(meta)) => {
                let valid_after = meta.lifetime().valid_after();
                request.set_last_consensus_date(std::cmp::max(valid_after, default_cutoff));
                request.push_old_consensus_digest(*meta.sha3_256_of_signed());
            }
            latest => {
                if let Err(e) = latest {
                    warn!("Error loading directory metadata: {}", e);
                }
                // If we don't have a consensus, then request one that's
                // "reasonably new".  That way, our clock is set far in the
                // future, we won't download stuff we can't use.
                request.set_last_consensus_date(default_cutoff);
            }
        }

        Ok(ClientRequest::Consensus(request))
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
}

/// A degree of readiness for a given directory state object.
#[derive(Debug, Copy, Clone)]
enum Readiness {
    /// There is no more information to download.
    Complete,
    /// There is more information to download, but we don't need to
    Usable,
}

/// A "state" object used to represent our progress in downloading a
/// directory.
///
/// These state objects are not meant to know about the network, or
/// how to fetch documents at all.  Instead, they keep track of what
/// information they are missing, and what to do when they get that
/// information.
///
/// Every state object has two possible transitions: "resetting", and
/// "advancing".  Advancing happens when a state has no more work to
/// do, and needs to transform into a different kind of object.
/// Resetting happens when this state needs to go back to an initial
/// state in order to start over -- either because of an error or
/// because the information it has downloaded is no longer timely.
trait DirState: Send {
    /// Return a human-readable description of this state.
    fn describe(&self) -> String;
    /// Return a list of the documents we're missing.
    ///
    /// If every document on this list were to be loaded or downloaded, then
    /// the state should either become "ready to advance", or "complete."
    ///
    /// This list should never _grow_ on a given state; only advancing
    /// or resetting the state should add new DocIds that weren't
    /// there before.
    fn missing_docs(&self) -> Vec<DocId>;
    /// Describe whether this state has reached `ready` status.
    fn is_ready(&self, ready: Readiness) -> bool;
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// Add one or more documents from our cache; returns 'true' if there
    /// was any change in this state.
    ///
    /// If `storage` is provided, then we should write any state changes into
    /// it.  (We don't read from it in this method.)
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        storage: Option<&Mutex<DynStore>>,
    ) -> Result<bool>;

    /// Add information that we have just downloaded to this state; returns
    /// 'true' if there as any change in this state.
    ///
    /// This method receives a copy of the original request, and
    /// should reject any documents that do not pertain to it.
    ///
    /// If `storage` is provided, then we should write any accepted documents
    /// into `storage` so they can be saved in a cache.
    // TODO: It might be good to say "there was a change but also an
    // error" in this API if possible.
    // TODO: It would be better to not have this function be async,
    // once the `must_not_suspend` lint is stable.
    // TODO: this should take a "DirSource" too.
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        storage: Option<&Mutex<DynStore>>,
    ) -> Result<bool>;
    /// Return a summary of this state as a [`DirStatus`].
    fn bootstrap_status(&self) -> event::DirStatus;

    /// Return a configuration for attempting downloads.
    fn dl_config(&self) -> Result<DownloadSchedule>;
    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>>;
    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead reset it and start over.
    fn reset_time(&self) -> Option<SystemTime>;
    /// Reset this state and start over.
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>>;
}

/// Try to upgrade a weak reference to a DirMgr, and give an error on
/// failure.
fn upgrade_weak_ref<T>(weak: &Weak<T>) -> Result<Arc<T>> {
    Weak::upgrade(weak).ok_or(Error::ManagerDropped)
}

/// At most how much age can we tolerate in a consensus?
///
/// TODO: Make this public and/or use it elsewhere; see arti#412.
const CONSENSUS_ALLOW_SKEW: Duration = Duration::from_secs(3600 * 48);

/// Given a time `now`, return the age of the oldest consensus that we should
/// request at that time.
fn default_consensus_cutoff(now: SystemTime) -> Result<SystemTime> {
    let cutoff = time::OffsetDateTime::from(now - CONSENSUS_ALLOW_SKEW);
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
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::docmeta::{AuthCertMeta, ConsensusMeta};
    use std::time::Duration;
    use tempfile::TempDir;
    use tor_netdoc::doc::{authcert::AuthCertKeyIds, netstatus::Lifetime};

    pub(crate) fn new_mgr<R: Runtime>(runtime: R) -> (TempDir, DirMgr<R>) {
        let dir = TempDir::new().unwrap();
        let config = DirMgrConfig::builder()
            .cache_path(dir.path())
            .build()
            .unwrap();
        let dirmgr = DirMgr::from_config(config, runtime, None, false).unwrap();

        (dir, dirmgr)
    }

    #[test]
    fn failing_accessors() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let (_tempdir, mgr) = new_mgr(rt);

            assert!(mgr.circmgr().is_err());
            assert!(mgr.opt_netdir().is_none());
        });
    }

    #[test]
    fn load_and_store_internals() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let (_tempdir, mgr) = new_mgr(rt);

            let now = SystemTime::now();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

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
            assert!(res.get(&d_bogus).is_none());
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
            let (_tempdir, mgr) = new_mgr(rt);

            let now = SystemTime::now();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

            // Try with an empty store.
            let req = mgr
                .make_consensus_request(now, ConsensusFlavor::Microdesc)
                .unwrap();
            match req {
                ClientRequest::Consensus(r) => {
                    assert_eq!(r.old_consensus_digests().count(), 0);
                    let date = r.last_consensus_date().unwrap();
                    assert!(date >= now - CONSENSUS_ALLOW_SKEW);
                    assert!(date <= now - CONSENSUS_ALLOW_SKEW + Duration::from_secs(3600));
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
            let req = mgr
                .make_consensus_request(now, ConsensusFlavor::Microdesc)
                .unwrap();
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
            let mut rng = rand::thread_rng();
            #[cfg(feature = "routerdesc")]
            let rd_ids: Vec<[u8; 20]> = (0..1000).map(|_| rng.gen()).collect();
            let md_ids: Vec<[u8; 32]> = (0..1000).map(|_| rng.gen()).collect();

            // Try an authcert.
            let query = DocQuery::AuthCert(vec![certid1]);
            let reqs = mgr.query_into_requests(query).unwrap();
            assert_eq!(reqs.len(), 1);
            let req = &reqs[0];
            if let ClientRequest::AuthCert(r) = req {
                assert_eq!(r.keys().next(), Some(&certid1));
            } else {
                panic!();
            }

            // Try a bunch of mds.
            let query = DocQuery::Microdesc(md_ids);
            let reqs = mgr.query_into_requests(query).unwrap();
            assert_eq!(reqs.len(), 2);
            assert!(matches!(reqs[0], ClientRequest::Microdescs(_)));

            // Try a bunch of rds.
            #[cfg(feature = "routerdesc")]
            {
                let query = DocQuery::RouterDesc(rd_ids);
                let reqs = mgr.query_into_requests(query).unwrap();
                assert_eq!(reqs.len(), 2);
                assert!(matches!(reqs[0], ClientRequest::RouterDescs(_)));
            }
        });
    }

    #[test]
    fn expand_response() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let (_tempdir, mgr) = new_mgr(rt);

            // Try a simple request: nothing should happen.
            let q = DocId::Microdesc([99; 32]).into();
            let r = &mgr.query_into_requests(q).unwrap()[0];
            let expanded = mgr.expand_response_text(r, "ABC".to_string());
            assert_eq!(&expanded.unwrap(), "ABC");

            // Try a consensus response that doesn't look like a diff in
            // response to a query that doesn't ask for one.
            let latest_id = DocId::LatestConsensus {
                flavor: ConsensusFlavor::Microdesc,
                cache_usage: CacheUsage::CacheOkay,
            };
            let q: DocQuery = latest_id.into();
            let r = &mgr.query_into_requests(q.clone()).unwrap()[0];
            let expanded = mgr.expand_response_text(r, "DEF".to_string());
            assert_eq!(&expanded.unwrap(), "DEF");

            // Now stick some metadata and a string into the storage so that
            // we can ask for a diff.
            {
                let mut store = mgr.store.lock().unwrap();
                let now = SystemTime::now();
                let day = Duration::from_secs(86400);
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
            let r = &mgr.query_into_requests(q).unwrap()[0];
            let expanded = mgr.expand_response_text(r, "hello".to_string());
            assert_eq!(&expanded.unwrap(), "hello");

            // Finally, try "expanding" a diff (by applying it and checking the digest.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 8382374ca766873eb0d2530643191c6eaa2c5e04afa554cbac349b5d0592d300
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(r, diff);

            assert_eq!(expanded.unwrap(), "line 1\nreplacement line\nline 3\n");

            // If the digest is wrong, that should get rejected.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 9999999999999999999999999999999999999999999999999999999999999999
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(r, diff);
            assert!(expanded.is_err());
        });
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn bool_resetter_works() {
        let bool = AtomicBool::new(false);
        fn example(bool: &AtomicBool) {
            bool.store(true, Ordering::SeqCst);
            let _resetter = BoolResetter {
                inner: bool,
                reset_to: false,
                ordering: Ordering::SeqCst,
            };
        }
        fn example_disarm(bool: &AtomicBool) {
            bool.store(true, Ordering::SeqCst);
            let resetter = BoolResetter {
                inner: bool,
                reset_to: false,
                ordering: Ordering::SeqCst,
            };
            resetter.disarm();
        }
        example(&bool);
        assert_eq!(bool.load(Ordering::SeqCst), false);
        example_disarm(&bool);
        assert_eq!(bool.load(Ordering::SeqCst), true);
    }
}
